// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
const button = document.querySelector("#auth")
const form = document.querySelector("#login")

async function Login() {
  const response = await window.fetch(`/api/login`, {
    method: 'POST',
    body: new URLSearchParams(new FormData(form)),
  })

  if (!response.ok) {
    let message = response.statusText
    try {
      message = await response.text()
    } catch {}

    throw new Error(message);
  }

  return response.status
}

function clearStatus() {
  form.classList.remove("failed")
  form.classList.remove("success")
}

function submit(evt){
  evt.preventDefault()
  button.disabled = true

  document.querySelector('.error').innerText = ""
  clearStatus()

  Login().then(() => {
    window.location = "/";
  }).catch((err) => {
    form.classList.add("failed")
    document.querySelector('.error').innerText = err
    console.error(err)
  }).finally(() => {
    form.classList.remove("requested")
    button.disabled = false
    setTimeout(clearStatus, 5000)
  })

  return false
}

button.addEventListener("click", submit)
form.addEventListener("submit", submit)
