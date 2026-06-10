const crypto = require('crypto')
const fs = require('fs')
const jose = require('node-jose')
const path = require('path')

const readFrom = (p) => fs.readFileSync(path.resolve(__dirname, p), 'utf8')

const signingPem = fs.readFileSync(
  path.resolve(__dirname, '../static/certs/spcp-key.pem'),
)

const hashToken = (token) => {
  const fullHash = crypto.createHash('sha256')
  fullHash.update(token, 'utf8')
  const fullDigest = fullHash.digest()
  const digestBuffer = fullDigest.slice(0, fullDigest.length / 2)
  if (Buffer.isEncoding('base64url')) {
    return digestBuffer.toString('base64url')
  } else {
    const fromBase64 = (base64String) =>
      base64String.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
    return fromBase64(digestBuffer.toString('base64'))
  }
}

const myinfo = {
  v3: JSON.parse(readFrom('../static/myinfo/v3.json')),
}

const oidc = {
  singPass: [
    ...Object.keys(myinfo.v3.personas).map((nric) => ({
      nric,
      uuid: myinfo.v3.personas[nric].uuid.value,
      claims: myinfo.v3.personas[nric],
      name: myinfo.v3.personas[nric].name.value,
    })),
  ],
  corpPass: [
    {
      nric: 'S8979373D',
      uuid: 'a9865837-7bd7-46ac-bef4-42a76a946424',
      name: 'Name of S8979373D',
      isSingPassHolder: true,
      uen: '123456789A',
    },
    {
      nric: 'S8116474F',
      uuid: 'f4b70aea-d639-4b79-b8d9-8ace5875f6b1',
      name: 'Name of S8116474F',
      isSingPassHolder: true,
      uen: '123456789A',
    },
    {
      nric: 'S8723211E',
      uuid: '178478de-fed7-4c03-a75e-e68c44d0d5f0',
      name: 'Name of S8723211E',
      isSingPassHolder: true,
      uen: '123456789A',
    },
    {
      nric: 'S5062854Z',
      uuid: '1bd2e743-8681-4079-a557-6a66a8d16386',
      name: 'Name of S5062854Z',
      isSingPassHolder: true,
      uen: '123456789B',
    },
    {
      nric: 'T0066846F',
      uuid: '14f7ee8f-9e64-4170-a529-e55ca7578e2b',
      name: 'Name of T0066846F',
      isSingPassHolder: true,
      uen: '123456789B',
    },
    {
      nric: 'F9477325W',
      uuid: '2135fe5c-d07b-49d3-b960-aabb0ff2e05a',
      name: 'Name of F9477325W',
      isSingPassHolder: false,
      uen: '123456789B',
    },
    {
      nric: 'S3000024B',
      uuid: 'b5630beb-e3ee-4a31-aec5-534cdc087fd8',
      name: 'Name of S3000024B',
      isSingPassHolder: true,
      uen: '123456789C',
    },
    {
      nric: 'S6005040F',
      uuid: '6c6745d9-e6c5-40ee-8c96-5d737ddbc5e4',
      name: 'Name of S6005040F',
      isSingPassHolder: true,
      uen: '123456789C',
    },
  ],
  create: {
    singPass: (
      { nric, uuid },
      iss,
      aud,
      nonce,
      accessToken = crypto.randomBytes(15).toString('hex'),
    ) => {
      let sub
      const sfa = {
        Y4581892I: { fid: 'G730Z-H5P96', coi: 'DE', RP: 'CORPPASS' },
        Y7654321K: { fid: '123456789', coi: 'CN', RP: 'IRAS' },
        Y1234567P: { fid: 'G730Z-H5P96', coi: 'MY', RP: 'CORPPASS' },
      }
      if (nric.startsWith('Y')) {
        const sfaAccount = sfa[nric]
          ? sfa[nric]
          : { fid: 'G730Z-H5P96', coi: 'DE', RP: 'CORPPASS' }
        sub = `s=${nric},fid=${sfaAccount.fid},coi=${sfaAccount.coi},u=${uuid}`
      } else {
        sub = `s=${nric},u=${uuid}`
      }
      const accessTokenHash = hashToken(accessToken)

      const refreshToken = crypto.randomBytes(20).toString('hex')
      const refreshTokenHash = hashToken(refreshToken)

      return {
        accessToken,
        refreshToken,
        idTokenClaims: {
          rt_hash: refreshTokenHash,
          at_hash: accessTokenHash,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
          iss,
          amr: ['pwd'],
          aud,
          sub,
          ...(nonce ? { nonce } : {}),
        },
      }
    },
    corpPass: async (
      { nric, uuid, name, isSingPassHolder, uen },
      iss,
      aud,
      nonce,
    ) => {
      const baseClaims = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
        iss,
        aud,
      }

      const sub = `s=${nric},uuid=${uuid},u=${uen}${nric},c=SG`

      const accessTokenClaims = {
        ...baseClaims,
        authorization: {
          EntityInfo: {},
          AccessInfo: {},
          TPAccessInfo: {},
        },
      }

      const signingKey = await jose.JWK.asKey(signingPem, 'pem')
      const accessToken = await jose.JWS.createSign(
        { format: 'compact' },
        signingKey,
      )
        .update(JSON.stringify(accessTokenClaims))
        .final()

      const accessTokenHash = hashToken(accessToken)

      const refreshToken = crypto.randomBytes(20).toString('hex')
      const refreshTokenHash = hashToken(refreshToken)

      return {
        accessToken,
        refreshToken,
        idTokenClaims: {
          ...baseClaims,
          rt_hash: refreshTokenHash,
          at_hash: accessTokenHash,
          amr: ['pwd'],
          sub,
          ...(nonce ? { nonce } : {}),
          userInfo: {
            CPAccType: 'User',
            CPUID_FullName: name,
            ISSPHOLDER: isSingPassHolder ? 'YES' : 'NO',
          },
          entityInfo: {
            CPEntID: uen,
            CPEnt_TYPE: 'UEN',
            CPEnt_Status: 'Registered',
            CPNonUEN_Country: '',
            CPNonUEN_RegNo: '',
            CPNonUEN_Name: '',
          },
        },
      }
    },
  },
}

module.exports = {
  oidc,
  myinfo,
}
