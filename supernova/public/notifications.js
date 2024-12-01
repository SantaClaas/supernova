/**
 *
 * @param {string} applicationServerKey - The public key of the VAPID key pair from the server encoded as base64 url safe.
 */
async function subscribe(applicationServerKey) {
  console.debug("ASK", applicationServerKey);
  const registration = await navigator.serviceWorker.getRegistration();
  const subscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey,
  });

  const json = subscription.toJSON();

  const response = await fetch("/notifications/subscriptions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(json),
  });
}
