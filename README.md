# Bulk form submitter

Web tool that submits the "Report suspicious activity" form
(https://linkreclamatiogrwc.uk/) once per target line and reports, per line,
whether it was sent, the confirmation code (`CF-XXXXXXXX`) or the reason it failed.

## Run

Requires Python 3.10+.

Windows:

```
start.bat
```

macOS / Linux:

```
sh start.sh
```

The first start creates `.venv`, installs Flask and Playwright, and downloads Chromium (~150 MB).
After that the same command starts in a couple of seconds. The UI opens at http://127.0.0.1:8000.

Manual alternative: `pip install -r requirements.txt` and then `python app.py`
(Chromium is downloaded automatically on the first submission if missing).

## Usage

1. Choose Submission Type (Domain / IP / URL).
2. Paste targets, one per line. Empty lines and duplicates are dropped.
3. Choose Threat Type, write Reason, optionally attach a JPG/JPEG/PNG/PDF up to 2 MB.
4. Press "Отправить". A Chromium window opens; for each line the tool loads the form,
   fills every field, attaches the file, accepts the terms and submits.
5. The results table updates live: `отправлено` + code, or `не отправлено` + reason.
   "Повторить" retries one line, "Повторить неудачные" retries all failed lines of that batch.

### Captcha

The form is protected by Google reCAPTCHA, and the server rejects submissions without it
(`Captcha verification failed`). The tool does not bypass the captcha: when a line reaches
that step, the status becomes `ждёт капчу` and the operator ticks "I'm not a robot" in the
Chromium window. Submission then continues automatically. If the captcha is not completed
within `CAPTCHA_TIMEOUT` seconds the line fails with a clear reason and can be retried.
If the form has no captcha, lines go through with no operator action at all.

## What is validated before sending

- Domain: valid hostname (IDN allowed); a URL in Domain mode is rejected.
- IP: valid IPv4 / IPv6.
- URL: absolute `http(s)://` URL, up to 2000 chars.
- Reason: required, up to 2000 chars.
- File: extension jpg/jpeg/png/pdf, size up to 2 MB, content matches the extension.

Invalid lines are marked failed with the reason and are not sent (fix them and start a new batch).

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `FORM_URL` | `https://linkreclamatiogrwc.uk/` | Form address |
| `PORT` / `HOST` | `8000` / `127.0.0.1` | UI address |
| `CAPTCHA_TIMEOUT` | `300` | Seconds to wait for the captcha per line |
| `HEADLESS` | `0` | `1` = hidden browser (only if the form has no captcha) |
| `OPEN_UI` | `1` | Open the UI in the default browser on start |

## Files

- `app.py`: web UI, API and the Playwright worker.
- `data/jobs.json`: history of batches and results (survives restarts).
- `data/responses/`: HTML of every form response, for debugging.
- `data/uploads/`: attached files.
- `data/browser-profile/`: Chromium profile.

## Why there is no Docker

The browser has to be visible so the operator can complete the captcha. A headed browser
inside a container needs a VNC/X setup, which is heavier than `start.bat`.
