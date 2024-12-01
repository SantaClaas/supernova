self.addEventListener("install", (event) => event.waitUntil(onInstall(event)));
self.addEventListener("activate", (event) =>
  event.waitUntil(onActivate(event)),
);
self.addEventListener("push", function (event) {
  const promiseChain = self.registration.showNotification(event.data.text());
  event.waitUntil(promiseChain);
});
self.addEventListener("pushsubscriptionchange", (event) => {
  //TODO https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerGlobalScope/pushsubscriptionchange_event
  console.log("Push subscription change", event);
});

async function onInstall(event) {
  console.info("Service worker: Install");
}

async function onActivate(event) {
  console.info("Service worker: Activate");
}

async function onPush(event) {
  console.info("Service worker: Push notification");
  const title = event.data.text();
  self.registration.showNotification(title);
}
