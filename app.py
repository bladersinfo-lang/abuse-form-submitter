"""Bulk submitter for the "Report suspicious activity" form.

One web UI, one background worker. The worker drives a real Chromium window
(Playwright): for every target line it opens the form, fills all fields,
waits for the reCAPTCHA to be completed in that window, submits, and records
the confirmation code (CF-XXXXXXXX) or the reason of failure.

Run:  python app.py      (UI on http://127.0.0.1:8000)
"""
import ipaddress
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, abort, jsonify, render_template_string, request

# ---------------------------------------------------------------- settings
FORM_URL = os.environ.get("FORM_URL", "https://linkreclamatiogrwc.uk/")
PORT = int(os.environ.get("PORT", "8000"))
HOST = os.environ.get("HOST", "127.0.0.1")
CAPTCHA_TIMEOUT = int(os.environ.get("CAPTCHA_TIMEOUT", "300"))  # seconds per row
HEADLESS = os.environ.get("HEADLESS", "0") == "1"  # only useful if the form has no captcha
OPEN_UI = os.environ.get("OPEN_UI", "1") == "1"

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
UPLOADS = os.path.join(DATA, "uploads")
RESPONSES = os.path.join(DATA, "responses")
PROFILE = os.path.join(DATA, "browser-profile")
STATE_FILE = os.path.join(DATA, "jobs.json")
for _d in (DATA, UPLOADS, RESPONSES):
    os.makedirs(_d, exist_ok=True)

SUBMISSION_TYPES = {"domain": "Domain", "ip": "IP", "url": "URL"}
THREAT_TYPES = ["Spam", "Phishing", "Malware", "Botnet C&C", "Fraud / Scam", "Other"]
ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".pdf"}
MAX_FILE = 2 * 1024 * 1024
MAX_REASON = 2000
CODE_RE = re.compile(r"\bCF-[A-Za-z0-9]{8}\b")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z][A-Za-z0-9-]{1,62}$")

# Row statuses
QUEUED, RUNNING, CAPTCHA, SENT, FAILED = "queued", "running", "captcha", "sent", "failed"
ACTIVE = {QUEUED, RUNNING, CAPTCHA}


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- storage
class Store:
    """Jobs kept in memory and mirrored to data/jobs.json after every change."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()
        self.jobs = {}
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    self.jobs = json.load(f)
            except (OSError, ValueError):
                self.jobs = {}
        # Rows that were in flight when the app stopped can be retried.
        for job in self.jobs.values():
            for row in job["rows"]:
                if row["status"] in ACTIVE:
                    row.update(status=FAILED, error="Прервано перезапуском приложения", updated=now())
        self.save()

    def save(self):
        with self.lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.jobs, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)

    def add(self, job):
        with self.lock:
            self.jobs[job["id"]] = job
            self.save()

    def get(self, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            return json.loads(json.dumps(job)) if job else None

    def list(self):
        with self.lock:
            jobs = sorted(self.jobs.values(), key=lambda j: j["created"], reverse=True)
            return json.loads(json.dumps(jobs))

    def update_row(self, job_id, idx, **fields):
        with self.lock:
            row = self.jobs[job_id]["rows"][idx]
            row.update(fields, updated=now())
            self.save()


store = Store(STATE_FILE)


# ---------------------------------------------------------------- validation
def validate_target(value, kind):
    """Return (normalized_value, error_text_or_None)."""
    v = value.strip()
    if kind == "domain":
        if "://" in v or "/" in v:
            return v, "Это похоже на URL, а выбран тип Domain"
        v = v.rstrip(".")
        try:
            ascii_v = v.encode("idna").decode("ascii")
        except UnicodeError:
            return v, "Некорректное доменное имя"
        if not DOMAIN_RE.match(ascii_v):
            return v, "Некорректное доменное имя"
        return v, None
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(v)), None
        except ValueError:
            return v, "Некорректный IP-адрес (нужен IPv4 или IPv6)"
    if kind == "url":
        if len(v) > 2000:
            return v, "URL длиннее 2000 символов"
        p = urlparse(v)
        if p.scheme not in ("http", "https") or not p.netloc:
            return v, "Некорректный URL (нужен полный адрес с http:// или https://)"
        return v, None
    return v, "Неизвестный тип"


def check_file(name, blob):
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_EXT:
        return "Файл должен быть JPG, JPEG, PNG или PDF"
    if len(blob) > MAX_FILE:
        return f"Файл больше 2 МБ ({len(blob):,} байт при лимите {MAX_FILE:,})".replace(",", " ")
    if len(blob) == 0:
        return "Файл пустой"
    magic_ok = (
        (ext in (".jpg", ".jpeg") and blob[:3] == b"\xff\xd8\xff")
        or (ext == ".png" and blob[:8] == b"\x89PNG\r\n\x1a\n")
        or (ext == ".pdf" and blob[:5] == b"%PDF-")
    )
    if not magic_ok:
        return "Содержимое файла не соответствует расширению"
    return None


def safe_name(name):
    base = os.path.basename(name or "file")
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._") or "file"
    return base[:100]


# ---------------------------------------------------------------- browser worker
class Worker(threading.Thread):
    """Owns the single Playwright browser. Rows are processed one at a time."""

    def __init__(self):
        super().__init__(daemon=True)
        self.q = queue.Queue()
        self.state = "idle"  # shown in the UI header

    def enqueue(self, job_id, idx):
        store.update_row(job_id, idx, status=QUEUED, error="", code="")
        self.q.put((job_id, idx))

    def run(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            ctx = None
            while True:
                job_id, idx = self.q.get()
                job = store.get(job_id)
                if not job or job["rows"][idx]["status"] != QUEUED:
                    continue
                self.state = "busy"
                store.update_row(job_id, idx, status=RUNNING,
                                 attempts=job["rows"][idx].get("attempts", 0) + 1)
                try:
                    if ctx is None or not self._alive(ctx):
                        ctx = self._launch(pw)
                    code = self._submit(ctx, job, idx)
                    store.update_row(job_id, idx, status=SENT, code=code, error="")
                except SubmitError as e:
                    store.update_row(job_id, idx, status=FAILED, error=str(e))
                except Exception as e:  # browser closed, network down, etc.
                    store.update_row(job_id, idx, status=FAILED, error=explain(e))
                    ctx = None if ctx is None or not self._alive(ctx) else ctx
                finally:
                    self.state = "idle" if self.q.empty() else "busy"

    @staticmethod
    def _alive(ctx):
        try:
            ctx.pages  # noqa: B018 - raises if the context is gone
            return ctx.browser is None or ctx.browser.is_connected()
        except Exception:
            return False

    @staticmethod
    def _launch(pw):
        kwargs = dict(user_data_dir=PROFILE, headless=HEADLESS, viewport={"width": 760, "height": 900},
                      args=["--window-size=800,1000"])
        try:
            return pw.chromium.launch_persistent_context(**kwargs)
        except Exception as e:
            if "Executable doesn't exist" not in str(e):
                raise
            # First run: download Chromium once, then retry.
            subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
            return pw.chromium.launch_persistent_context(**kwargs)

    def _submit(self, ctx, job, idx):
        row = job["rows"][idx]
        kind, target = job["submission_type"], row["target"]
        page = ctx.new_page()
        try:
            try:
                resp = page.goto(FORM_URL, wait_until="domcontentloaded", timeout=60000)
            except Exception as e:
                raise SubmitError(f"Не удалось открыть форму: {explain(e)}")
            if resp is not None and resp.status >= 400:
                raise SubmitError(f"Сайт формы ответил HTTP {resp.status}")
            try:
                page.wait_for_selector("form #submission_type", state="attached", timeout=30000)
            except Exception:
                raise SubmitError("На странице не найдена форма (структура сайта изменилась?)")

            set_select(page, "#submission_type", kind)
            page.fill(f"#{kind}", target)
            set_select(page, "#threat_type", job["threat_type"])
            page.fill("#reason", job["reason"])
            if job.get("file_path"):
                page.set_input_files("#attachment", job["file_path"])
            page.check("input[name=accept_terms]")

            invalid = page.evaluate(
                """() => [...document.querySelector('form').elements]
                    .filter(e => e.willValidate && !e.checkValidity())
                    .map(e => (e.name || e.id) + ': ' + e.validationMessage)""")
            if invalid:
                raise SubmitError("Форма не приняла данные: " + "; ".join(invalid))

            self._wait_captcha(page, job["id"], idx)

            try:
                with page.expect_navigation(timeout=60000) as nav:
                    page.click("form button[type=submit]")
                resp = nav.value
            except Exception as e:
                raise SubmitError(f"После нажатия Submit сайт не ответил: {explain(e)}")

            html = page.content()
            with open(os.path.join(RESPONSES, f"{job['id']}_{idx + 1}.html"), "w", encoding="utf-8") as f:
                f.write(html)
            text = page.inner_text("body")
            m = CODE_RE.search(text)
            if m:
                return m.group(0)
            errors = page.eval_on_selector_all(
                ".alert, .field-error", "els => els.map(e => e.innerText.trim()).filter(Boolean)")
            status = resp.status if resp else "?"
            if errors:
                raise SubmitError("Форма отклонила отправку: " + " | ".join(errors))
            raise SubmitError(f"Нет кода подтверждения в ответе (HTTP {status}); "
                              f"ответ сохранён в data/responses/{job['id']}_{idx + 1}.html")
        finally:
            try:
                page.close()
            except Exception:
                pass

    def _wait_captcha(self, page, job_id, idx):
        state = page.evaluate(
            """() => ({has: !!document.querySelector('.g-recaptcha'),
                       val: (document.querySelector('[name="g-recaptcha-response"]') || {}).value || ''})""")
        if not state["has"]:
            return  # form without captcha: submit straight away
        store.update_row(job_id, idx, status=CAPTCHA)
        try:
            page.bring_to_front()
            page.locator(".g-recaptcha").scroll_into_view_if_needed(timeout=5000)
        except Exception:
            pass
        deadline = time.time() + CAPTCHA_TIMEOUT
        while time.time() < deadline:
            val = page.evaluate(
                "() => (document.querySelector('[name=\"g-recaptcha-response\"]') || {}).value || ''")
            if val:
                store.update_row(job_id, idx, status=RUNNING)
                return
            page.wait_for_timeout(500)
        raise SubmitError(f"Капча не пройдена за {CAPTCHA_TIMEOUT} с")


class SubmitError(Exception):
    """Failure with a reason that is already human-readable."""


def set_select(page, selector, value):
    """The form hides native <select>s behind a custom dropdown; set the native one and fire change."""
    got = page.evaluate(
        """([sel, val]) => { const s = document.querySelector(sel);
              if (!s) return null;
              if (![...s.options].some(o => o.value === val && !o.disabled)) return '';
              s.value = val; s.dispatchEvent(new Event('change', {bubbles: true})); return s.value; }""",
        [selector, value])
    if got is None:
        raise SubmitError(f"На форме нет поля {selector}")
    if got != value:
        raise SubmitError(f"В поле {selector} нет варианта «{value}»")


def explain(e):
    msg = str(e).splitlines()[0] if str(e) else e.__class__.__name__
    low = msg.lower()
    if "has been closed" in low or "target closed" in low or "browser has been closed" in low:
        return "Окно браузера было закрыто во время отправки"
    if "timeout" in low:
        return "Превышено время ожидания ответа сайта"
    if "net::err_name_not_resolved" in low:
        return "Домен формы не резолвится (нет сети/DNS)"
    if "net::err_internet_disconnected" in low or "net::err_connection" in low:
        return "Нет соединения с сайтом формы"
    return msg[:300]


worker = Worker()

# ---------------------------------------------------------------- web app
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


@app.get("/")
def index():
    return render_template_string(PAGE, types=SUBMISSION_TYPES, threats=THREAT_TYPES,
                                  form_url=FORM_URL, captcha_timeout=CAPTCHA_TIMEOUT)


@app.post("/api/jobs")
def create_job():
    kind = request.form.get("submission_type", "")
    threat = request.form.get("threat_type", "")
    reason = (request.form.get("reason") or "").strip()
    lines = [ln.strip() for ln in (request.form.get("targets") or "").splitlines() if ln.strip()]

    errors = []
    if kind not in SUBMISSION_TYPES:
        errors.append("Выберите Submission Type")
    if threat not in THREAT_TYPES:
        errors.append("Выберите Threat Type")
    if not reason:
        errors.append("Заполните Reason")
    elif len(reason) > MAX_REASON:
        errors.append(f"Reason длиннее {MAX_REASON} символов")
    if not lines:
        errors.append("Добавьте хотя бы одну цель")

    job_id = uuid.uuid4().hex[:10]
    file_path = file_name = None
    up = request.files.get("attachment")
    if up and up.filename:
        blob = up.read()
        err = check_file(up.filename, blob)
        if err:
            errors.append(err)
        else:
            file_name = safe_name(up.filename)
            os.makedirs(os.path.join(UPLOADS, job_id), exist_ok=True)
            file_path = os.path.join(UPLOADS, job_id, file_name)
            with open(file_path, "wb") as f:
                f.write(blob)
    if errors:
        return jsonify(errors=errors), 400

    rows, seen, dupes = [], set(), 0
    for ln in lines:
        target, err = validate_target(ln, kind)
        key = target.lower()
        if key in seen:
            dupes += 1
            continue
        seen.add(key)
        rows.append(dict(target=target, status=FAILED if err else QUEUED, code="", error=err or "",
                         retryable=not err, attempts=0, updated=now()))

    job = dict(id=job_id, created=now(), submission_type=kind, threat_type=threat, reason=reason,
               file_path=file_path, file_name=file_name, duplicates_removed=dupes, rows=rows)
    store.add(job)
    for i, r in enumerate(rows):
        if r["status"] == QUEUED:
            worker.enqueue(job_id, i)
    return jsonify(public(store.get(job_id)))


@app.get("/api/jobs")
def list_jobs():
    return jsonify(jobs=[public(j) for j in store.list()], worker=worker.state)


@app.get("/api/jobs/<job_id>")
def get_job(job_id):
    job = store.get(job_id)
    if not job:
        abort(404)
    return jsonify(public(job))


@app.post("/api/jobs/<job_id>/retry")
def retry(job_id):
    job = store.get(job_id)
    if not job:
        abort(404)
    wanted = (request.get_json(silent=True) or {}).get("rows")
    n = 0
    for i, r in enumerate(job["rows"]):
        if wanted is not None and i not in wanted:
            continue
        if r["status"] == FAILED and r.get("retryable", True):
            worker.enqueue(job_id, i)
            n += 1
    return jsonify(requeued=n)


def public(job):
    job = dict(job)
    job.pop("file_path", None)
    return job


# ---------------------------------------------------------------- UI
PAGE = r"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Массовая отправка жалоб</title>
<style>
 :root{--bg:#0f1720;--card:#17222f;--line:#2a3a4d;--text:#e8eef5;--muted:#93a4b8;--acc:#4a8fe7;--ok:#3fbf7f;--bad:#ff6b6b;--wait:#f0b44c}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,Segoe UI,sans-serif}
 .wrap{max-width:1100px;margin:0 auto;padding:20px 16px}
 h1{font-size:20px;margin:0 0 4px} .sub{color:var(--muted);margin:0 0 18px;font-size:13px}
 .grid{display:grid;grid-template-columns:380px 1fr;gap:18px} @media(max-width:900px){.grid{grid-template-columns:1fr}}
 .card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px}
 label{display:block;font-weight:600;font-size:12px;margin:0 0 5px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
 .f{margin-bottom:14px} select,textarea,input[type=file]{width:100%;background:#0f1923;color:var(--text);border:1px solid var(--line);border-radius:5px;padding:8px;font:inherit}
 textarea{resize:vertical} #targets{min-height:140px;font-family:ui-monospace,Consolas,monospace}
 .seg{display:flex;gap:6px} .seg input{display:none} .seg span{display:block;padding:7px 14px;border:1px solid var(--line);border-radius:5px;cursor:pointer}
 .seg input:checked+span{background:var(--acc);border-color:var(--acc);color:#fff}
 button{background:var(--acc);color:#fff;border:0;border-radius:5px;padding:9px 18px;font:600 14px system-ui;cursor:pointer}
 button.ghost{background:transparent;border:1px solid var(--line);color:var(--text);padding:5px 10px;font-weight:500;font-size:13px}
 button:disabled{opacity:.5;cursor:default}
 .err{color:var(--bad);font-size:13px;margin-top:8px;white-space:pre-line} .hint{color:var(--muted);font-size:12px;margin-top:4px}
 table{width:100%;border-collapse:collapse;font-size:13px} th,td{text-align:left;padding:7px 6px;border-bottom:1px solid var(--line);vertical-align:top}
 th{color:var(--muted);font-weight:600} td.t{font-family:ui-monospace,Consolas,monospace;word-break:break-all}
 .st{font-weight:600;white-space:nowrap} .sent{color:var(--ok)} .failed{color:var(--bad)} .queued{color:var(--muted)} .running,.captcha{color:var(--wait)}
 .code{font-family:ui-monospace,Consolas,monospace;font-weight:700;color:var(--ok)}
 .jobhead{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px}
 .meta{color:var(--muted);font-size:12px} .job{margin-bottom:18px} .banner{background:#3a2e12;border-left:4px solid var(--wait);padding:8px 12px;margin-bottom:12px;font-size:13px;display:none}
</style></head><body><div class="wrap">
<h1>Массовая отправка формы</h1>
<p class="sub">Форма: {{ form_url }} · одна строка = одна отправка · капча отмечается в окне браузера, лимит {{ captcha_timeout }} с на строку</p>
<div class="grid">
<form id="f" class="card" enctype="multipart/form-data">
  <div class="f"><label>Submission Type</label><div class="seg">
   {% for k, v in types.items() %}<label style="all:unset"><input type="radio" name="submission_type" value="{{k}}" {% if loop.first %}checked{% endif %}><span>{{v}}</span></label>{% endfor %}
  </div></div>
  <div class="f"><label for="targets">Цели, по одной на строку</label>
   <textarea id="targets" name="targets" placeholder="example.com&#10;example.org"></textarea><div class="hint" id="cnt">0 строк</div></div>
  <div class="f"><label for="threat">Threat Type</label><select id="threat" name="threat_type">
   <option value="">— выберите —</option>{% for t in threats %}<option>{{t}}</option>{% endfor %}</select></div>
  <div class="f"><label for="reason">Reason</label><textarea id="reason" name="reason" rows="4" maxlength="2000"></textarea></div>
  <div class="f"><label for="att">Файл (необязательно)</label><input id="att" type="file" name="attachment" accept=".jpg,.jpeg,.png,.pdf">
   <div class="hint">JPG, JPEG, PNG или PDF, до 2 МБ</div></div>
  <button id="go" type="submit">Отправить</button><div class="err" id="ferr"></div>
</form>
<div><div class="banner" id="banner">Ждём капчу: отметьте «I'm not a robot» в открытом окне браузера, дальше отправка пойдёт сама.</div><div id="jobs"></div></div>
</div></div>
<script>
const $=s=>document.querySelector(s);
const LBL={queued:'в очереди',running:'отправляется',captcha:'ждёт капчу',sent:'отправлено',failed:'не отправлено'};
const TYPES={{ types|tojson }};
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
$('#targets').addEventListener('input',()=>{const n=$('#targets').value.split('\n').filter(x=>x.trim()).length;$('#cnt').textContent=n+' строк';});
$('#f').addEventListener('submit',async e=>{
  e.preventDefault(); $('#ferr').textContent=''; $('#go').disabled=true;
  try{const r=await fetch('/api/jobs',{method:'POST',body:new FormData($('#f'))});
      const d=await r.json(); if(!r.ok){$('#ferr').textContent=(d.errors||['Ошибка']).join('\n');return}
      $('#targets').value=''; $('#cnt').textContent='0 строк'; load();
  }catch(err){$('#ferr').textContent='Сервер недоступен: '+err}finally{$('#go').disabled=false}
});
async function retry(id,rows){await fetch('/api/jobs/'+id+'/retry',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(rows?{rows}:{})});load()}
function render(jobs){
  $('#banner').style.display=jobs.some(j=>j.rows.some(r=>r.status==='captcha'))?'block':'none';
  if(!jobs.length){$('#jobs').innerHTML='<div class="card meta">Отправок пока нет.</div>';return}
  $('#jobs').innerHTML=jobs.map(j=>{
    const c=s=>j.rows.filter(r=>r.status===s).length, fail=j.rows.filter(r=>r.status==='failed'&&r.retryable).length;
    return `<div class="card job"><div class="jobhead"><div><b>${esc(TYPES[j.submission_type])} · ${esc(j.threat_type)}</b>
      <div class="meta">${esc(j.created)} · отправлено ${c('sent')}/${j.rows.length}${j.file_name?' · файл '+esc(j.file_name):''}${j.duplicates_removed?' · дублей убрано: '+j.duplicates_removed:''}</div></div>
      ${fail?`<button class="ghost" onclick="retry('${j.id}')">Повторить неудачные (${fail})</button>`:''}</div>
      <table><tr><th>#</th><th>Цель</th><th>Статус</th><th>Код / причина</th><th></th></tr>
      ${j.rows.map((r,i)=>`<tr><td>${i+1}</td><td class="t">${esc(r.target)}</td><td class="st ${r.status}">${LBL[r.status]||r.status}</td>
        <td>${r.code?`<span class="code">${esc(r.code)}</span>`:esc(r.error)}${r.attempts>1?`<div class="meta">попыток: ${r.attempts}</div>`:''}</td>
        <td>${r.status==='failed'&&r.retryable?`<button class="ghost" onclick="retry('${j.id}',[${i}])">Повторить</button>`:''}</td></tr>`).join('')}
      </table></div>`}).join('');
}
async function load(){try{const d=await (await fetch('/api/jobs')).json();render(d.jobs)}catch(e){}}
load(); setInterval(load,1500);
</script></body></html>"""


if __name__ == "__main__":
    worker.start()
    url = f"http://{HOST}:{PORT}/"
    print(f"UI: {url}   form: {FORM_URL}")
    if OPEN_UI:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
