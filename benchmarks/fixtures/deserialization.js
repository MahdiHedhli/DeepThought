'use strict'

const sanitize = require('./internal/sanitize')

function vulnerableDeserialize (str) {
  return (new Function('return ' + str))()
}

function hardenedDeserialize (str, unsafe) {
  if (!unsafe) str = sanitize(str)
  return (new Function('"use strict"; return ' + str))()
}

module.exports = { vulnerableDeserialize, hardenedDeserialize }
