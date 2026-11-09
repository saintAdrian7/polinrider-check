# Cleaning up a PolinRider infection

Work through the sections in order. Skipping ahead to "clean the repo" is the mistake everyone makes: the branches come back infected within hours, because the thing pushing them is a stolen credential, not your local copy.

Everything below is reversible or backed up except where it says otherwise.

---

## 0. Before you touch anything

- **Do not open the infected folders in VS Code** (or any editor that runs project tasks). A `.vscode/tasks.json` task can run the payload the moment the folder opens.
- **Do not run `npm`, `npx`, `yarn` or `pnpm` in them.** Install scripts and a tampered npm CLI both re-launch the malware.
- **Do not `git pull` or check out the infected branches.** Read them through git's object store instead (section 4 shows how).
- If check 5 of the scanner flagged this machine, treat every password saved in your browsers, every SSH key and every wallet on it as stolen. Section 2 covers that.

---

## 1. Cut off the pusher

The payload reaches GitHub through a credential, never through your working copy. We watched a clean sweep of 115 branches get re-infected within a day, three times, until the credential was revoked. After revocation the next sweep held.

1. **GitHub personal access tokens.** <https://github.com/settings/tokens> and <https://github.com/settings/personal-access-tokens>. Delete every token you don't recognise, then every token you do. Make new ones afterwards.
2. **GitHub OAuth and GitHub Apps.** <https://github.com/settings/applications>. Revoke anything you don't use daily. Pay attention to deploy platforms.
3. **Deploy platforms connected to the repos** (Vercel, Netlify, Render, Railway, Cloudflare Pages). The malware steals their tokens and pushes through their GitHub integration, so your own security log stays clean. In each platform: disconnect the GitHub integration, rotate the platform's tokens, reconnect.
4. **Find out who pushed.** Personal account: <https://github.com/settings/security-log>, filter `action:git.push`. Organisation: *Settings → Audit log*. The entry shows the actor, the IP and the token type. A commit's *author* is forged by the malware (it reuses your name and email), so never go by the author.
5. **Block force-pushes.** On every repository: *Settings → Branches → Add rule* for the default branch and any long-lived branches, tick *Do not allow force pushes* (or use a ruleset). This stops the re-infection mechanism even if a credential slips through.
6. **Rotate any secret that was ever committed** to an infected repo: `.env` values, API keys, database URLs, Stripe keys. The payload exfiltrates environment variables and files.

---

## 2. Clean this machine (if check 5 found anything)

**Windows**

1. Close all editors and terminals. In Task Manager, end any `node.exe` or `python.exe` you can't account for.
2. Open PowerShell as administrator and remove the startup entries the scanner listed:
   ```powershell
   Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "<EntryName>"
   schtasks /Delete /TN "<TaskName>" /F
   ```
3. Delete the lock file if it was reported: `%LOCALAPPDATA%\Temp\tmp7A863DD1.tmp`.
4. **Reinstall Node.js** from <https://nodejs.org>. Uninstall first, delete `C:\Program Files\nodejs`, then install. This replaces the tampered `npm\lib\cli.js`. Check it afterwards: the file should be under 1 KB.
5. Remove any malicious global package the scanner listed: `npm uninstall -g <name>` (after the reinstall).

**macOS / Linux**

1. `pkill -f temp_auto_push; pkill -f fa-solid-400` and kill any `node` process you can't account for.
2. Remove the launch agent, crontab line or shell-startup line the scanner reported (`~/Library/LaunchAgents/*.plist`, `crontab -e`, `~/.zshrc`, `~/.bashrc`).
3. Reinstall Node (`brew reinstall node`, or your distribution's package, or `nvm uninstall` + `nvm install`). Check `$(npm prefix -g)/lib/node_modules/npm/lib/cli.js` is under 1 KB afterwards.

**Either platform, afterwards**

- Change every password your browsers had saved, starting with email, GitHub, npm, cloud providers and banking. Turn on two-factor authentication where it was off.
- Regenerate SSH keys (`~/.ssh`) and replace them on GitHub and your servers.
- Move funds out of any crypto wallet whose files lived on this machine, to a wallet created elsewhere.
- Re-run the scanner.

---

## 3. Clean a repository locally

Do this in a fresh terminal, not in an editor. For each repository the scanner listed:

1. **Payload in a config file** (`postcss.config.js`, `jest.config.js`, `tailwind.config.js`, `next.config.mjs`, …). Run the helper from this repo:
   ```bash
   node /path/to/polinrider-check/clean-config.js path/to/postcss.config.js --dry-run
   node /path/to/polinrider-check/clean-config.js path/to/postcss.config.js
   ```
   It cuts the line at the start of the payload, drops the padding, removes the `createRequire` shim from the top of `.mjs` files, and keeps the original as `<file>.polinrider.bak`. Open the result and confirm the last real line is intact (usually `};` or `export default config;`). Delete the `.bak` once you're happy.
2. **A fake font file** (`public/fonts/fa-solid-400.woff2` or similar, reported as "not a real font"). The whole file is payload. Delete it; do not try to edit it. Real sibling fonts such as `fa-solid-900.woff2` and `fa-regular-400.woff2` stay.
3. **Dropped files.** Delete `temp_auto_push.bat`, `temp_interactive_push.bat`, `config.bat`, `branch_structure.json`.
4. **`.gitignore`.** Remove only the injected lines (`temp_auto_push.bat`, `temp_interactive_push.bat`, `config.bat`, `branch_structure.json`). Leave the rest.
5. **`.vscode/tasks.json`.** Remove the task that has `"runOn": "folderOpen"` and runs `curl`, `wget` or `node … .woff2`. If the file only contained that task, delete the file.
6. **`package.json`.** Remove the malicious dependency, delete `node_modules` and the lock file, then `npm install` (only after section 2 is done).
7. **Reflog** (if "amended commits" was reported and you've done the above):
   ```bash
   git reflog expire --expire=now --all && git gc --prune=now
   ```
8. Commit the cleanup. Re-run the scanner on the folder; it should be clean.

---

## 4. Clean the remote branches

The remote is usually where the infection lives, on every branch at once, while your checkout is clean. Don't check those branches out. Rebuild each one from git's object store and force-push the clean commit.

**First decide which side holds the real work.** The malware force-pushes the remote *behind* your local work on some branches, and on others the remote has colleagues' commits your local copy never fetched. So for each infected branch:

```bash
git fetch --all --prune
git branch backup/<branch>-$(date +%Y%m%d) <branch>        # if you have it locally
git merge-base --is-ancestor <branch> origin/<branch> && echo "local is behind or equal"
git merge-base --is-ancestor origin/<branch> <branch> && echo "origin is behind or equal"
git log --oneline <branch>...origin/<branch>                 # what differs
```

- **Only on the remote, or remote is ahead:** clean *from the remote* (below). It is the only or newest copy.
- **Local is ahead or equal:** push your clean local branch over it: `git push --force-with-lease origin <branch>`.
- **Diverged:** look at the differing commits. Ignore anything with "PolinRider", "malware" or "security" in the subject; those are the malware's own commits or earlier cleanups. Keep whichever side has the real work, then clean it.

**Clean from the remote without checking out.** Per infected branch, with `FILE` as the infected config path:

```bash
BRANCH=main
FILE=postcss.config.js
REPO=.

# 1. Read the infected blob by SHA (never "ref:path", which some shells mangle)
SHA=$(git -C "$REPO" ls-tree "origin/$BRANCH" -- "$FILE" | awk '{print $3}')
git -C "$REPO" cat-file -p "$SHA" > /tmp/infected.js

# 2. Clean it with the helper
node /path/to/polinrider-check/clean-config.js /tmp/infected.js
# (writes /tmp/infected.js in place; inspect it)

# 3. Build a new commit on top of the remote tip with just that file replaced
export GIT_INDEX_FILE=/tmp/clean-index
git -C "$REPO" read-tree "origin/$BRANCH"
NEWBLOB=$(git -C "$REPO" hash-object -w /tmp/infected.js)
git -C "$REPO" update-index --cacheinfo 100644,"$NEWBLOB","$FILE"
# For a fake font or dropped file, remove it instead:
#   git -C "$REPO" update-index --force-remove public/fonts/fa-solid-400.woff2
TREE=$(git -C "$REPO" write-tree)
unset GIT_INDEX_FILE
COMMIT=$(git -C "$REPO" commit-tree "$TREE" -p "origin/$BRANCH" -m "Remove injected payload")

# 4. Verify the new commit's file is clean before pushing
git -C "$REPO" ls-tree "$COMMIT" -- "$FILE" | awk '{print $3}' | xargs git -C "$REPO" cat-file -p | tail -c 300

# 5. Push
git -C "$REPO" push --force-with-lease origin "$COMMIT:refs/heads/$BRANCH"
```

If the push is rejected with *stale info*, someone pushed between your fetch and your push. First confirm it isn't just a stale local ref (run a normal `git fetch` and compare `git ls-remote origin <branch>` over a minute). If the remote tip really moved, the pusher's credential is still live: go back to section 1 before cleaning again.

Repeat for each branch, then run the scanner with the remote option. It should report clean on every branch.

---

## 5. Afterwards

- Re-scan the next day, and again a week later. Re-infection means a credential you missed.
- Tell your collaborators to run the scanner too. One infected machine on the team re-infects the shared repos.
- Report the repository at <https://opensourcemalware.com> so others get warned.
- If you got here through a "coding test" or "take-home assignment" repo from a recruiter, that was the lure. Don't run the next one.

## What the pieces are

| Thing | What it does |
|---|---|
| Padded line at the end of a config | The payload. Decrypts itself in layers and runs on `node` startup of any tool that loads the config (Next.js, Jest, PostCSS, Tailwind). |
| `public/fonts/fa-solid-400.woff2` (text) | The same payload hidden as a font, run by a VS Code task on folder open. |
| `.vscode/tasks.json` with `runOn: folderOpen` | Executes the fake font or downloads a stage from a `*.vercel.app` host. |
| `temp_auto_push.bat` | Sets the system clock back to your last commit's date, amends that commit with the payload under your name, restores the clock, force-pushes. This is why infected commits look like yours and look old. |
| `branch_structure.json` | A map of every branch, written before the malware repoints them all at one commit. If you see this, check your branch tips, not just the files. |
| Injected `.gitignore` lines | Hide the files above from `git status`. Often the only trace left after the batch file deletes itself. |
| Oversized `npm/lib/cli.js` | The machine-level foothold. Re-launches the malware on every npm command. |
