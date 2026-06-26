# Contributing to Secure OpenClaw Sandbox

## Setup

### 1. Fork i kloniranje

Forkaš originalni repo na GitHubu, zatim kloniraš **svoj fork**:

```bash
git clone https://github.com/<tvoj-username>/secure-openclaw-sandbox.git
cd secure-openclaw-sandbox
```

### 2. Dodaj upstream remote

```bash
git remote add upstream https://github.com/SmailG/secure-openclaw-sandbox.git

# Provjeri da imaš oba remota:
git remote -v
# origin    https://github.com/<tvoj-username>/secure-openclaw-sandbox (fetch)
# origin    https://github.com/<tvoj-username>/secure-openclaw-sandbox (push)
# upstream  https://github.com/SmailG/secure-openclaw-sandbox (fetch)
# upstream  https://github.com/SmailG/secure-openclaw-sandbox (push)
```

## Workflow za svaku izmjenu

### 3. Sync sa originalom prije rada

```bash
git fetch upstream
git checkout main
git merge upstream/main
git push origin main
```

### 4. Napravi novi branch

```bash
git checkout -b naziv-moje-izmjene
```

### 5. Napravi izmjene, commit i push

```bash
git add <fajlovi>
git commit -m "kratki opis izmjene"
git push origin naziv-moje-izmjene
```

### 6. Otvori Pull Request

Na GitHubu idi na tvoj fork → **Compare & pull request** → target je `SmailG/secure-openclaw-sandbox`.

## Napomene

- `origin` = tvoj fork (ovdje pushuješ)
- `upstream` = originalni repo (odavde povlačiš izmjene)
- Uvijek pravi **novi branch** za svaku izmjenu, nikad direktno na `main`
- PR mora proći `make test` provjeru prije mergea
