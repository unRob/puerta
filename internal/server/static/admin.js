import * as webauthn from "./webauthn.js"

// const host = document.location.protocol + "//" + document.location.host
const host = "http://localhost:8081"

class UserInfoPanel extends HTMLElement {
  constructor(user) {
    super()
    let template = document.getElementById("user-info-panel")
    const shadowRoot = this.attachShadow({ mode: "open" })
    const panel = template.content.cloneNode(true)

    let handle = user.handle
    panel.querySelector('h3').innerHTML = user.name
    panel.querySelector('input[name=name]').value = user.name

    panel.querySelector('form').action = panel.querySelector('form').action.replace(":id", handle)
    panel.querySelector('pre').textContent = handle

    panel.querySelector('input[name=greeting]').value = user.greeting
    panel.querySelector('input[name=schedule]').value = user.schedule
    panel.querySelector('input[name=expires]').value = user.expires
    panel.querySelector('input[name=max_ttl]').value = user.max_ttl
    panel.querySelector('input[name=is_admin]').checked = user.is_admin
    panel.querySelector('input[name=second_factor]').checked = user.second_factor
    shadowRoot.appendChild(panel)
  }
}
customElements.define("user-info-panel", UserInfoPanel)

class REXRow extends HTMLElement {
  constructor(rex) {
    super()
    let template = document.getElementById("rex-record")
    const shadowRoot = this.attachShadow({ mode: "open" })
    const row = template.content.cloneNode(true)

    row.querySelector('.log-record-timestamp').innerText = (new Date(rex.timestamp)).toISOString()
    row.querySelector('.log-record-user').innerText = rex.user
    row.querySelector('.log-record-status').innerHTML = !rex.error ? "ok" : `<strong>${rex.error}</strong> ${rex.failure}`
    row.querySelector('.log-record-second_factor').innerText = rex.second_factor ? "✓" : ""
    row.querySelector('.log-record-ip_address').innerText = rex.ip_address
    row.querySelector('.log-record-user_agent').innerText = rex.user_agent

    shadowRoot.appendChild(row)
  }
}
customElements.define("rex-record", REXRow)

async function fetchUsers() {
  console.debug("fetching users")
  let response = await window.fetch(`${host}/api/user`, {credentials: "include"})

  if (!response.ok) {
    alert("Could not load users")
    return
  }

  let json = {}
  try {
    json = await response.json()
  } catch (err) {
    alert(err)
    return
  }

  document.querySelector("#user-list").replaceChildren(...json.map(u => new UserInfoPanel(u)))
}

async function fetchLog() {
  console.debug("fetching log")
  let response = await window.fetch(`${host}/api/log?last=20`, {credentials: "include"})

  if (!response.ok) {
    alert("Could not load log")
    return
  }

  let json = {}
  try {
    json = await response.json()
  } catch (err) {
    alert(err)
    return
  }

  document.querySelector("#rex-records").replaceChildren(...json.map(rex => {
    const tr = document.createElement("tr")
    tr.classList.add("rex-staus-" + (!rex.error ? "ok" : "failure"))

    const status = !rex.error ? "ok" : `<strong>${rex.error}</strong> ${rex.failure}`
    tr.innerHTML = `<th class="log-record-timestamp">${(new Date(rex.timestamp)).toISOString()}</th>
    <td class="log-record-user">${rex.user}</td>
    <td class="log-record-status">${status}</td>
    <td class="log-record-second_factor">${rex.second_factor ? "✓" : ""}</td>
    <td class="log-record-ip_address">${rex.ip_address}</td>
    <td class="log-record-user_agent">${rex.user_agent}</td>`
    // tr.appendChild(new REXRow(record))
    return tr
  }))
}

async function CreateUser(form) {
  let user = Object.fromEntries(new FormData(form))
  delete(user.id)
  if (user.expires != "") {
    user.expires = (new Date(user.expires)).toISOString()
  } else {
    delete(user.expires)
  }

  if (user.max_ttl == "") {
    delete(user.max_ttl)
  }

  if (user.schedule == "") {
    delete(user.schedule)
  }


  user.admin = (user.admin == "on")
  user.second_factor = (user.second_factor == "on")

  let response = await webauthn.withAuth(host + form.getAttribute("action"), {
    credentials: "include",
    method: "POST",
    body: JSON.stringify(user),
    headers: {
      'Content-Type': 'application/json'
    }
  })

  if (!response.ok) {
    throw new Error("Could not create user:", response)
  }

  window.location.reload()
}



async function switchTab() {
  let tabName = window.location.hash.toLowerCase().replace("#", "")
  let activate = async () => true
  console.log(`switching to tab ${tabName}`)
  switch (tabName) {
    case "crear":
      break;
    case "registro":
      activate = fetchLog
      break;
    case "":
      tabName = "invitades"
    case "invitades":
      activate = fetchUsers
      break;
    default:
      throw new Error(`unknown tab ${tabName}`)
  }
  console.log(`activating tab ${tabName}`)

  let open = document.querySelector(".tab-open")
  if (open) {
    open.classList.remove("tab-open")
    open.classList.add("hidden")
  }
  let tab = document.querySelector(`#${tabName}`)
  tab.classList.add("tab-open")
  tab.classList.remove("hidden")

  await activate(tab)
}

window.addEventListener("load", async function() {
  const form = document.querySelector("#create-user")
  form.addEventListener("submit", async (evt) => {
    evt.preventDefault()
    await CreateUser(form)
  })

  switchTab()
})

window.addEventListener('hashchange', () => {
  switchTab()
})

