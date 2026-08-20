/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns/promises'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateOrLocalIp (ip: string): boolean {
  const cleanIp = ip.trim().toLowerCase()

  // IPv4 check
  if (cleanIp.includes('.')) {
    const parts = cleanIp.split('.').map(Number)
    if (parts.length !== 4 || parts.some(isNaN)) {
      return true
    }
    const [o1, o2, o3, o4] = parts

    // Loopback: 127.0.0.0/8
    if (o1 === 127) return true

    // Private networks (RFC 1918):
    // 10.0.0.0/8
    if (o1 === 10) return true
    // 172.16.0.0/12
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return true
    // 192.168.0.0/16
    if (o1 === 192 && o2 === 168) return true

    // Link-local: 169.254.0.0/16
    if (o1 === 169 && o2 === 254) return true

    // Unspecified / current network / broadcast:
    // 0.0.0.0/8
    if (o1 === 0) return true

    return false
  }

  // IPv6 check
  if (cleanIp.includes(':')) {
    if (cleanIp === '::1' || cleanIp === '::' || cleanIp === '0:0:0:0:0:0:0:1' || cleanIp === '0:0:0:0:0:0:0:0') {
      return true
    }
    // Check for IPv4-mapped IPv6 address (e.g., ::ffff:192.168.1.1)
    if (cleanIp.startsWith('::ffff:')) {
      const ipv4Part = cleanIp.substring(7)
      if (ipv4Part.includes('.')) {
        return isPrivateOrLocalIp(ipv4Part)
      }
    }
    // Link-local (fe80::/10)
    if (cleanIp.startsWith('fe8') || cleanIp.startsWith('fe9') || cleanIp.startsWith('fea') || cleanIp.startsWith('feb')) {
      return true
    }
    // Unique Local Addresses (fc00::/7)
    if (cleanIp.startsWith('fc') || cleanIp.startsWith('fd')) {
      return true
    }
    return false
  }

  return true
}

async function validateUrlForSsrf (urlStr: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(urlStr)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }

    const hostname = parsedUrl.hostname
    if (!hostname) {
      return false
    }

    try {
      const lookupResult = await dns.lookup(hostname)
      if (isPrivateOrLocalIp(lookupResult.address)) {
        return false
      }
    } catch {
      return false
    }

    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const isChallengeUrl = url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null
      if (isChallengeUrl) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!isChallengeUrl) {
          const isSafe = await validateUrlForSsrf(url)
          if (!isSafe) {
            next(new Error('Blocked illegal activity'))
            return
          }
        }
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
