self.addEventListener("activate", event => {
  console.log("Service worker activated");
});


self.addEventListener('push', (event) => {
  let notification = event.data.text();
  console.log(`got notification: ${notification}`)
  console.log(`evt: `, event)
  self.registration.showNotification(notification);
});
