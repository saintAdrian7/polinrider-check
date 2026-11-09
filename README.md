# PolinRider check

A free scanner for the **PolinRider** malware (also seen as **TasksJacker**), a campaign that hides an obfuscated JavaScript payload inside developers' git repositories, force-pushes it to GitHub, and steals browser passwords, wallet files and CI/CD tokens from the machines that open those repositories.

It is read-only. Running it changes nothing. It tells you whether your projects, your remote branches and your machine show signs of the malware, and [CLEANUP.md](CLEANUP.md) tells you what to do if they do.

## Scan in two minutes

**Windows (PowerShell)**

```powershell
git clone https://github.com/saintAdrian7/polinrider-check
cd polinrider-check
powershell -ExecutionPolicy Bypass -File .\scan.ps1 C:\path\to\your\projects
```

**macOS / Linux**

```bash
git clone https://github.com/saintAdrian7/polinrider-check
cd polinrider-check
chmod +x scan.sh
./scan.sh ~/path/to/your/projects
```

Point it at the folder that holds all your projects, not a single repository. Then run it again with the remote option, because the payload is usually on GitHub while your local copy looks clean:

```powershell
.\scan.ps1 C:\path\to\your\projects -Remote
```
```bash
./scan.sh ~/path/to/your/projects --remote
```

The remote scan fetches every branch of every repository and reads the files straight out of git's objects. Nothing is checked out, so a payload can't run.

A clean run ends with `RESULT: clean`. Anything else lists each finding with the file and what was matched, and exits with code 1.

## What it checks

| # | Check | Why |
|---|---|---|
| 1 | **Payload hidden in files.** Known signature strings, the family's structural traits, any line over 2000 characters hidden behind 200+ spaces, the `createRequire(import.meta.url)` shim in `.mjs` configs, and "font" files (`.woff`, `.woff2`, `.ttf`, `.eot`) that are really text. | The payload is appended to the last line of a config file after hundreds of spaces, so an editor shows nothing. Newer builds hide the whole payload in a fake `public/fonts/fa-solid-400.woff2`. Every tracked text file is checked, not just configs. |
| 2 | **Repository artifacts.** `temp_auto_push.bat`, `temp_interactive_push.bat`, `config.bat`, `branch_structure.json`, the `.gitignore` lines that hide them, amended commits in the reflog. | The malware's push script amends your last commit with a rewound clock and force-pushes it, then deletes itself but leaves the `.gitignore` lines behind. |
| 3 | **VS Code tasks.** `.vscode/tasks.json` tasks that run on folder open and download something or run a "font" with node, plus the known command-and-control hosts. | This is how the fake font gets executed: opening the folder in VS Code is enough. |
| 4 | **npm packages.** Dependencies on the actor's packages (`tailwindcss-style-animate` and six others). | These were the original droppers, delivered through fake job-interview "coding test" repositories. |
| 5 | **This machine.** The size of npm's own `lib/cli.js`, globally installed packages, Windows Run keys and scheduled tasks, macOS launch agents, crontab and shell startup files, the lock file left in Temp. | An infected machine has a 1 MB+ `cli.js` instead of a few hundred bytes, and the malware re-spawns from it on every `npm` command. |
| 6 | **Remote branches** (with `-Remote` / `--remote`). Checks 1 to 4 against every branch on every remote. | The infection is pushed to GitHub with a forged author and date. Your checkout stays clean, so a local scan alone says "clean" while every branch on the remote is infected. |

## If it finds something

Read [CLEANUP.md](CLEANUP.md). The order matters:

1. **Stop the spread first.** Don't open the infected folders in an editor or run `npm` in them. Revoke your GitHub personal access tokens and OAuth app authorisations, and the tokens of any deploy service connected to those repos (Vercel, Netlify, Render, Railway). Until you do, the cleaned branches get re-infected within hours.
2. **Clean the machine** if check 5 found anything: reinstall Node and npm, remove the startup entries, change the passwords your browser had saved.
3. **Clean the repositories**, local and remote, with the steps and the `clean-config.js` helper in CLEANUP.md.
4. **Turn on branch protection** that blocks force-pushes, and re-scan the next day.

## What this is based on

The indicators come from the public write-ups by [OpenSourceMalware](https://github.com/OpenSourceMalware/PolinRider) and from cleaning this infection out of some 130 branches across two organisations between August and September 2026. Several checks here exist because the string signatures published at the time missed what we were actually looking at: a rebuilt payload with fresh constants, the fake-font vector, the ESM shim left behind by partial cleanups, and the fact that the remote was infected while every local checkout scanned clean.

The scripts are original code under the MIT licence. Indicators are facts, not code, and are reproduced with credit.

## Limitations

- Signature strings match known builds only. The structural checks (padded long line, fake font, shim) are what catch new builds, and they can in rare cases flag a legitimate minified file that someone committed on one line with heavy indentation. Look at the flagged line before deleting anything.
- The remote scan is only as good as your fetch. If a fetch needs a login that never completes, that remote's branches are skipped silently. Run `git fetch --all` in the repository yourself to see the error.
- It does not inspect `node_modules`. Reinstalling dependencies after cleaning `package.json` is part of the cleanup.
- It does not remove anything. That is deliberate: what to remove depends on whether the local copy or the remote holds the real work, and CLEANUP.md walks through deciding that.
