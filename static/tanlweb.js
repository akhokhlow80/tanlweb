function pushNotification(message) {
  let notification = document.createElement("div")
  notification.classList.add("notification")
  notification.classList.add("notification-fatal")
  notification.textContent = message
  document.getElementById("notifications-container").appendChild(notification)
}

document.addEventListener("htmx:sendError", function(evt) {
  pushNotification("Network error")
})

document.addEventListener("htmx:responseError", function(evt) {
  pushNotification("Error: " + evt.detail.xhr.status + " " + evt.detail.xhr.statusText)
})

function timestampToISO(timestamp) {
  return new Date(timestamp*1000).toLocaleDateString('en-CA')
}

function convertTimeStamps() {
    document.querySelectorAll("input[data-unix-timestamp]").forEach((input) => {
    input.value = timestampToISO(Number(input.getAttribute("data-unix-timestamp")))
  })
  document.querySelectorAll(":not(input)[data-unix-timestamp]").forEach((el) => {
    el.textContent = timestampToISO(Number(el.getAttribute("data-unix-timestamp")))
  })
}

document.addEventListener("htmx:afterSettle", function(evt) { convertTimeStamps() })
document.addEventListener("DOMContentLoaded", function(evt) { convertTimeStamps() })
