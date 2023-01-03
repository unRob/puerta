const button = document.querySelector("#open button")
const form = document.querySelector("#open")
import * as webauthn from "./webauthn.js"

// const host = document.location.protocol + "//" + document.location.host
const host = "http://localhost:8081"

async function RequestToEnter() {
  console.debug("requesting to enter")
  let response = await webauthn.withAuth(`${host}/api/rex`, {
    method: 'POST',
    credentials: "include"
  })

  if (!response.ok) {
    let message = response.statusText
    try {
      let json = await response.json()
      if (json.message) {
        message = `${message}: ${json.message}`
      }
    } catch {}

    throw new Error(message);
  }

  let json = {}
  try {
    json = await response.json()
  } catch {}

  if (json.status == "ok") {
    console.debug("Door opened")
  }

  return response.status
}


function clearStatus() {
  form.classList.remove("failed")
  form.classList.remove("success")
}

button.addEventListener("click", function(evt){
  evt.preventDefault()
  button.disabled = true

  clearStatus()

  RequestToEnter().then(() => {
    form.classList.add("success")
  }).catch((err) => {
    form.classList.add("failed")
    console.error(`Error: ${err}`)
  }).finally(() => {
    form.classList.remove("requested")
    button.disabled = false
    setTimeout(clearStatus, 5000)
  })

  return false
})
