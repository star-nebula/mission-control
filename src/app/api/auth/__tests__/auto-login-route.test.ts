import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  createSession: vi.fn((): { token: string; expiresAt: number } => ({ token: 'tok-from-auto-login', expiresAt: Math.floor(Date.now() / 1000) + 3600 })),
  getAllUsers: vi.fn((): Array<Record<string, unknown>> => []),
  logAuditEvent: vi.fn(),
  needsFirstTimeSetup: vi.fn((): boolean => false),
  findExposedAddresses: vi.fn(async (_port: number, _options?: unknown): Promise<string[]> => []),
  nonLoopbackAddresses: vi.fn((): string[] => []),
}))

vi.mock('@/lib/auth', () => ({
  createSession: mocks.createSession,
  getAllUsers: () => mocks.getAllUsers(),
}))
vi.mock('@/lib/db', () => ({
  logAuditEvent: mocks.logAuditEvent,
  needsFirstTimeSetup: () => mocks.needsFirstTimeSetup(),
}))
vi.mock('@/lib/auto-login-probe', () => ({
  findExposedAddresses: (port: number, options: unknown) => mocks.findExposedAddresses(port, options),
  nonLoopbackAddresses: () => mocks.nonLoopbackAddresses(),
}))
vi.mock('@/lib/logger', () => ({ logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() } }))

import { GET } from '@/app/api/auth/auto-login/route'

const ADMIN = { id: 7, username: 'admin', role: 'admin', provider: 'local', is_approved: 1, workspace_id: 1 }

function buildRequest(path = '/api/auth/auto-login', host = '127.0.0.1:3000'): Request {
  return new Request(`http://${host}${path}`, { headers: { host, 'user-agent': 'vitest-harness' } })
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.createSession.mockReturnValue({ token: 'tok-from-auto-login', expiresAt: Math.floor(Date.now() / 1000) + 3600 })
  mocks.getAllUsers.mockReturnValue([ADMIN])
  mocks.needsFirstTimeSetup.mockReturnValue(false)
  mocks.findExposedAddresses.mockResolvedValue([])
  mocks.nonLoopbackAddresses.mockReturnValue([])
  process.env.MC_AUTO_LOGIN = '1'
  delete process.env.AUTH_USER
})

async function locationOf(response: Response): Promise<string> {
  const location = response.headers.get('location')
  expect(location).not.toBeNull()
  return location as string
}

describe('auto-login route', () => {
  it('mints a session and sets the cookie when every check passes', async () => {
    const response = await GET(buildRequest('/api/auth/auto-login?next=/chat'))

    expect(response.status).toBe(307)
    expect(await locationOf(response)).toBe('http://127.0.0.1:3000/chat')
    expect(response.headers.get('set-cookie')).toContain('mc-session=tok-from-auto-login')
    expect(mocks.createSession).toHaveBeenCalledWith(7, '127.0.0.1', 'vitest-harness', 1)
    expect(mocks.logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: 'auto_login', actor: 'admin' }))
  })

  it('does nothing at all while the flag is off', async () => {
    delete process.env.MC_AUTO_LOGIN

    const response = await GET(buildRequest())

    expect(await locationOf(response)).toBe('http://127.0.0.1:3000/login')
    expect(mocks.findExposedAddresses).not.toHaveBeenCalled()
    expect(mocks.createSession).not.toHaveBeenCalled()
    expect(response.headers.get('set-cookie')).toBeNull()
  })

  it('refuses a request whose Host is not loopback', async () => {
    const response = await GET(buildRequest('/api/auth/auto-login?next=/chat', '192.168.1.5:3000'))

    expect(await locationOf(response)).toBe('http://192.168.1.5:3000/login')
    expect(mocks.findExposedAddresses).not.toHaveBeenCalled()
    expect(mocks.createSession).not.toHaveBeenCalled()
  })

  it('refuses and reports when the port answers on a non-loopback interface', async () => {
    mocks.nonLoopbackAddresses.mockReturnValue(['192.168.1.5'])
    mocks.findExposedAddresses.mockResolvedValue(['192.168.1.5'])

    const response = await GET(buildRequest('/api/auth/auto-login?next=/chat'))

    expect(await locationOf(response)).toBe('http://127.0.0.1:3000/login')
    expect(mocks.findExposedAddresses).toHaveBeenCalledWith(3000, { addresses: ['192.168.1.5'] })
    expect(mocks.createSession).not.toHaveBeenCalled()
  })

  it('sends a fresh install to /setup instead of inventing a user', async () => {
    mocks.getAllUsers.mockReturnValue([])
    mocks.needsFirstTimeSetup.mockReturnValue(true)

    const response = await GET(buildRequest())

    expect(await locationOf(response)).toBe('http://127.0.0.1:3000/setup')
    expect(mocks.createSession).not.toHaveBeenCalled()
  })

  it('refuses an existing user that login would also refuse', async () => {
    mocks.getAllUsers.mockReturnValue([{ ...ADMIN, provider: 'google' }])
    expect(await locationOf(await GET(buildRequest()))).toBe('http://127.0.0.1:3000/login')

    mocks.getAllUsers.mockReturnValue([{ ...ADMIN, is_approved: 0 }])
    expect(await locationOf(await GET(buildRequest()))).toBe('http://127.0.0.1:3000/login')
    expect(mocks.createSession).not.toHaveBeenCalled()
  })

  it('lands on the dashboard when next points off this origin', async () => {
    const response = await GET(buildRequest('/api/auth/auto-login?next=//evil.com'))

    expect(await locationOf(response)).toBe('http://127.0.0.1:3000/')
    expect(mocks.createSession).toHaveBeenCalledTimes(1)
  })

  it('honours AUTH_USER rather than assuming the admin username', async () => {
    process.env.AUTH_USER = 'Dev.Machine'
    // The unconfigured account sorts first, so "take whoever is there" is caught.
    mocks.getAllUsers.mockReturnValue([
      { ...ADMIN, id: 3, username: 'admin' },
      { ...ADMIN, id: 9, username: 'dev.machine' },
    ])

    const response = await GET(buildRequest('/api/auth/auto-login?next=/settings'))

    expect(await locationOf(response)).toBe('http://127.0.0.1:3000/settings')
    expect(mocks.createSession).toHaveBeenCalledWith(9, '127.0.0.1', 'vitest-harness', 1)
    expect(mocks.logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ actor: 'dev.machine' }))
  })

  it('refuses when the configured account does not exist', async () => {
    process.env.AUTH_USER = 'operator'

    const response = await GET(buildRequest())

    expect(await locationOf(response)).toBe('http://127.0.0.1:3000/login')
    expect(mocks.createSession).not.toHaveBeenCalled()
  })
})
