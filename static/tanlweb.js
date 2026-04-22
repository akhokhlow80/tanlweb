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

function timestampFormatter(timestamp, format) {
  const date = new Date(timestamp*1000)
  const locale = "en-GB"
  const useAgo = new Date() - date <= 30*24*60*60*1000
  switch (format) {
  case "local-datetime":
    return date.toLocaleDateString(locale) + " " + date.toLocaleTimeString(locale)
  case "local-datetime-with-ago":
    let formatted = ' ' + date.toLocaleDateString(locale) + " " + date.toLocaleTimeString(locale)
    if (useAgo)
      formatted += " (" + timeago.format(date, 'en_short') + ")"
    return formatted
  case "ago":
    if (useAgo)
      return timeago.format(date, 'en_short')
    else
      return date.toLocaleDateString(locale) + " " + date.toLocaleTimeString(locale)
  default:
    console.error("Invalid timestamp format '" + format + "'")
  }
}

function convertTimeStamps() {
  document.querySelectorAll("input[timestamp]").forEach((el) => {
    el.textContent = timestampFormatter(
      Number(el.getAttribute("timestamp")),
      el.getAttribute("timestamp-format")
    )
  })
  document.querySelectorAll(":not(input)[timestamp]").forEach((el) => {
    el.textContent = timestampFormatter(
      Number(el.getAttribute("timestamp")),
      el.getAttribute("timestamp-format")
    )
  })
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).catch(err => console.error('Failed to copy: ', err));
}

document.addEventListener("htmx:afterSettle", function(evt) { convertTimeStamps() })
document.addEventListener("DOMContentLoaded", function(evt) { convertTimeStamps() })
setInterval(convertTimeStamps, 20 * 1000)
