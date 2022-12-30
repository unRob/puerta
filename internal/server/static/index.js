const button = document.querySelector("#open button")
const form = document.querySelector("#open")
const { create: createCredentials, get: getCredentials } = hankoWebAuthn;

async function RequestToEnter() { 
  console.debug("requesting to enter")
  let response = await window.fetch(`/api/rex`, {
    method: 'POST',
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

  if (json.webauthn) {
    try {
      if (json.webauthn == "register") {
        await register(json.data)
      } else if (json.webauthn == "login"){
        await login(json.data)
      }
    } catch(err) {
      console.error("webauthn failure", err)
    }
  } else if (json.status == "ok") {
    console.debug("Door opened")
  }

  return response.status
}

async function register(data) {
  console.debug("creating credentials")
  const credential = await createCredentials(data);

  console.debug(`exchanging credential: ${JSON.stringify(credential)}`)
  let response = await window.fetch(`/api/rex`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(credential)
  })

  console.debug("sent credential creation request")

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
}

async function login(data) {
  console.debug("fetching passkey")
  const credential = await getCredentials(data);

  console.debug(`exchanging credential: ${JSON.stringify(credential)}`)
  let response = await window.fetch(`/api/rex`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(credential)
  })

  console.debug("sent passkey")

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
