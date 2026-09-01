import { createHash } from 'node:crypto'

import { beforeEach, describe, expect, it, vi } from 'vitest'

const { netFetchMock, openExternalMock } = vi.hoisted(() => ({
  netFetchMock: vi.fn(),
  openExternalMock: vi.fn()
}))

vi.mock('electron', () => ({
  app: { getLocale: () => 'en-US' },
  net: { fetch: netFetchMock },
  shell: { openExternal: openExternalMock }
}))

const { authorizeTokenDanceApiKey } = await import('../tokenDanceOAuth')

function base64UrlEncode(buffer: Buffer): string {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

describe('authorizeTokenDanceApiKey', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('uses a loopback callback and S256 PKCE before returning the exchanged API key', async () => {
    let authorizationUrl: URL | undefined
    let callbackResponse: Promise<Response> | undefined

    openExternalMock.mockImplementation(async (rawUrl: string) => {
      authorizationUrl = new URL(rawUrl)
      const callbackUrl = new URL(authorizationUrl.searchParams.get('callback_url')!)
      callbackUrl.searchParams.set('code', 'authorization-code')
      callbackResponse = fetch(callbackUrl)
    })
    netFetchMock.mockResolvedValue(
      new Response(JSON.stringify({ key: '  td-secret-key  ' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      })
    )

    await expect(authorizeTokenDanceApiKey()).resolves.toBe('td-secret-key')
    const browserResponse = await callbackResponse

    expect(browserResponse?.status).toBe(200)
    expect(await browserResponse?.text()).toContain('Authentication Successful')
    expect(authorizationUrl?.origin).toBe('https://tokendance.space')
    expect(authorizationUrl?.pathname).toBe('/auth')
    expect(authorizationUrl?.searchParams.get('app_url')).toBe('https://fresh-mushroom.vercel.app')
    expect(authorizationUrl?.searchParams.get('key_name')).toBe('Cherry Studio')
    expect(authorizationUrl?.searchParams.get('code_challenge_method')).toBe('S256')

    const callbackUrl = new URL(authorizationUrl!.searchParams.get('callback_url')!)
    expect(callbackUrl.hostname).toBe('127.0.0.1')
    expect(callbackUrl.port).not.toBe('')
    expect(callbackUrl.pathname).toBe('/oauth/tokendance/callback')
    expect(callbackUrl.searchParams.get('state')).toMatch(/^[a-f0-9]{32}$/)

    const [, request] = netFetchMock.mock.calls[0]
    const body = JSON.parse(String(request.body))
    expect(body).toMatchObject({
      code: 'authorization-code',
      code_challenge_method: 'S256'
    })
    expect(body.code_verifier).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(authorizationUrl?.searchParams.get('code_challenge')).toBe(
      base64UrlEncode(createHash('sha256').update(body.code_verifier).digest())
    )
    expect(netFetchMock).toHaveBeenCalledWith(
      'https://tokendance.space/portal/api/v1/auth/keys',
      expect.objectContaining({ method: 'POST', headers: { 'Content-Type': 'application/json' } })
    )
  })
})
