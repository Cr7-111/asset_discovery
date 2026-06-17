const apiBase = "https://api.corp-demo.test";
const opsConsole = "https://console.corp-demo.test/login";
const ssoEntry = "https://sso.corp-demo.test/auth";

async function boot() {
  await fetch("/api/feature-flags");
  await fetch("/graphql");
  await fetch(`${apiBase}/api/users`);
  console.log("ops", opsConsole, ssoEntry);
}

boot().catch(() => {});

