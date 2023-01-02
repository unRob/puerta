const button = document.querySelector("#open button")
const form = document.querySelector("#open")
const { create: createCredentials, get: getCredentials } = hankoWebAuthn;

const userList = document.querySelector("#user-list > ul")


customElements.define(
  "user-info-panel",
  class extends HTMLElement {
    constructor() {
      super()
      let template = document.getElementById("user-info-panel")
      const shadowRoot = this.attachShadow({ mode: "open" })
      const panel = template.content.cloneNode(true)

      panel.querySelector('h3').textContent = this.getAttribute('name')
      panel.querySelector('name').value = this.getAttribute('name')
      panel.querySelector('pre').textContent = this.getAttribute('handle')

      panel.querySelector('greeting').value = this.getAttribute('greeting')
      panel.querySelector('schedule').value = this.getAttribute('schedule')
      panel.querySelector('expires').value = this.getAttribute('expires')
      panel.querySelector('max_ttl').value = this.getAttribute('ttl')
      panel.querySelector('is_admin').checked = this.hasAttribute('admin')
      panel.querySelector('second_factor').checked = this.hasAttribute('second_factor')
      shadowRoot.appendChild(panel)
    }
  }
);

async function fetchUsers() {
  console.debug("fetching users")
  let response = await window.fetch("/api/user")

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

  userList.replaceChildren(json.map(u => {
    const ip = document.createElement("user-info-panel")
    ip.setAttribute("name", u.name)
    ip.setAttribute("handle", u.handle)

    ip.setAttribute('greeting', u.greeting)
    ip.setAttribute('schedule', u.schedule)
    ip.setAttribute('expires', u.expires)
    ip.setAttribute('max_ttl', u.ttl)
    if (u.admin) {
      ip.setAttribute('is_admin', "")
    }
    if (u.second_factor) {
      ip.setAttribute('second_factor', "")
    }

    return ip
  }))
}



