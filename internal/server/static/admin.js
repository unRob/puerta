const button = document.querySelector("#open button")
const form = document.querySelector("#open")

const userList = document.querySelector("#user-list > ul")

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

customElements.define(
  "user-info-panel",
  UserInfoPanel
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

  json.forEach(u => {
    const ip = new UserInfoPanel(u)
    ip.setAttribute("data-name", u.name)
    ip.setAttribute("data-handle", u.handle)

    ip.setAttribute('data-greeting', u.greeting)
    ip.setAttribute('data-schedule', u.schedule)
    ip.setAttribute('data-expires', u.expires)
    ip.setAttribute('data-max_ttl', u.max_ttl)
    if (u.admin) {
      ip.setAttribute('data-is_admin', "")
    }
    if (u.second_factor) {
      ip.setAttribute('data-second_factor', "")
    }

    return userList.append(ip)
  })
}

window.addEventListener("load", async function() {
  await fetchUsers()
})
