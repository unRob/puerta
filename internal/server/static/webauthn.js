const { create: createCredentials, get: getCredentials } = hankoWebAuthn;

const charsToEncode = /[\u007f-\uffff]/g;
function JSONtob64(data) {
  return btoa(JSON.stringify(data).replace(charsToEncode, (c) => '\\u'+('000'+c.charCodeAt(0).toString(16)).slice(-4)))
}

function b64ToJSON(encoded) {
  return JSON.parse(decodeURIComponent(atob(encoded).split('').map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')))
}

export async function withAuth(target, config) {
  console.log(`webauthn: issuing api request: ${target}`)
  const response = await window.fetch(target, config)
  console.debug(`webauthn: issued api request: ${target}`)

  if (!response.ok) {
    console.debug(`webauthn: failed request to ${target}`)
    return response
  }

  console.log(Object.fromEntries(response.headers))
  const challengeHeader = response.headers.get("webauthn")
  if (!challengeHeader || challengeHeader == "") {
    console.debug(`webauthn: success without auth`)
    return response
  }


  let [step, data] = challengeHeader.split(" ")
  if (step == "") {
    throw `webauthn: Invalid challenge received from server: ${response.headers.get("webauthn")}`
  }

  console.info(`webauthn: server issued <${step}> challenge, decoding`)
  let challenge = b64ToJSON(data)

  if (step == "register") {
    // server told us to register new credentials
    // we try to do that
    await register(challenge, target)
    // and retry the original request if successful
    return await withAuth(target, config)
  } else if (step == "login") {
    // server told us to use existing credential for request
    return await login(challenge, target, config)
  }

  throw `Unknown webauthn step: <${kind}>`
}

async function register(challenge) {
  console.info("webauthn: creating credentials")
  const credential = await createCredentials(challenge);

  console.debug(`webauthn: registering credentials with server: ${JSON.stringify(credential)}`)
  let response = await window.fetch("/api/webauthn/register", {
    credentials: "include",
    body: JSON.stringify(credential),
    headers: {
      'Content-type': 'application/json'
    }
  })

  if (!response.ok) {
    let message = response.statusText
    try {
      let json = await response.json()
      if (json.message) {
        message = `${message}: ${json.message}`
      }
    } catch {}

    throw new Error(`webauthn: failed to register credentials: ${message}`);
  }

  console.info("webauthn: created credentials")
}

async function login(challenge, target, config) {
  console.info("webauthn: fetching stored client credentials")
  const credential = await getCredentials(challenge);

  config.credentials = "include"
  config.headers = config.headers || {}
  config.headers.webauthn = JSONtob64(credential)

  console.info(`webauthn: issuing authenticated request to ${target}`)
  let response = await window.fetch(target, config)

  if (!response.ok) {
    let message = response.statusText
    try {
      let json = await response.json()
      if (json.message) {
        message = `${message}: ${json.message}`
      }
    } catch {}

    throw new Error(`webauthn: got error from authenticated request: ${message}`);
  }

  console.info("webauthn: sucessfully sent authenticated request")
  return response
}