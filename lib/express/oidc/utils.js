const assertions = require('../../assertions')

const buildAssertURL = (redirectURI, authCode, state) =>
  `${redirectURI}?code=${encodeURIComponent(
    authCode,
  )}&state=${encodeURIComponent(state)}`

const idGenerator = {
  singPass: ({ nric, name }) => {
    const persona = assertions.myinfo.v3.personas[nric]
    const displayName = persona?.name?.value || name
    if (persona?.privileges && displayName) {
      return `${persona.privileges} - ${displayName}`
    }
    if (displayName) {
      return `${nric} - ${displayName}`
    }
    return nric
  },
  corpPass: ({ nric, uen }) => `${nric} / UEN: ${uen}`,
}

const customProfileFromHeaders = {
  singPass: (req) => {
    const customNricHeader = req.header('X-Custom-NRIC')
    const customUuidHeader = req.header('X-Custom-UUID')
    if (!customNricHeader || !customUuidHeader) {
      return false
    }
    return { nric: customNricHeader, uuid: customUuidHeader }
  },
  corpPass: (req) => {
    const customNricHeader = req.header('X-Custom-NRIC')
    const customUuidHeader = req.header('X-Custom-UUID')
    const customUenHeader = req.header('X-Custom-UEN')
    if (!customNricHeader || !customUuidHeader || !customUenHeader) {
      return false
    }
    return {
      nric: customNricHeader,
      uuid: customUuidHeader,
      uen: customUenHeader,
    }
  },
}

module.exports = {
  buildAssertURL,
  idGenerator,
  customProfileFromHeaders,
}
