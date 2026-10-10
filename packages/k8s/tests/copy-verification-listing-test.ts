import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { execFile } from 'child_process'
import { promisify } from 'util'
import { localCalculateOutputHashSorted } from '../src/k8s'
import { listDirVerificationCommand } from '../src/k8s/utils'

// Protect entry membership and scan failure at the real find/stat boundary.
describe('copy verification listing', () => {
  let root: string
  let source: string
  let destination: string
  const unusual = "space ' quote\tline\nbreak"
  const run = promisify(execFile)
  const hash = async (directory: string): Promise<string> =>
    localCalculateOutputHashSorted([
      'sh',
      '-c',
      listDirVerificationCommand(directory)
    ])

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'hook-verification-listing-'))
    source = path.join(root, "source ' quoted")
    destination = path.join(root, 'destination')
    fs.mkdirSync(source)
    fs.mkdirSync(path.join(source, 'empty'))
    fs.writeFileSync(path.join(source, unusual), 'payload')
    fs.symlinkSync('empty', path.join(source, '--directory-link'))
    fs.symlinkSync('absent', path.join(source, 'dangling'))
    fs.cpSync(source, destination, { recursive: true, verbatimSymlinks: true })
  })

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true })
  })

  it('preserves non-directory records and excludes only directory sizes', async () => {
    const result = await run('sh', ['-c', listDirVerificationCommand(source)])
    const expected = [
      'd .',
      'd ./empty',
      `7 ./${unusual}`,
      '5 ./--directory-link',
      '6 ./dangling'
    ].join('\n')
    expect(result.stdout.trimEnd().split('\n').sort()).toEqual(
      expected.split('\n').sort()
    )
    fs.mkdirSync(path.join(destination, '_runner_hook_responses'))
    fs.writeFileSync(
      path.join(destination, '_runner_hook_responses', 'response'),
      'excluded'
    )
    expect(await hash(destination)).toBe(await hash(source))
  })

  test.each(['empty', '--directory-link', unusual])(
    'rejects loss of included entry %s',
    async entry => {
      fs.rmSync(path.join(destination, entry), { recursive: true })
      expect(await hash(destination)).not.toBe(await hash(source))
    }
  )

  it('rejects size changes and directory-to-file replacement', async () => {
    fs.appendFileSync(path.join(destination, unusual), 'changed size')
    expect(await hash(destination)).not.toBe(await hash(source))
    fs.writeFileSync(path.join(destination, unusual), 'payload')
    fs.rmSync(path.join(destination, 'empty'), { recursive: true })
    fs.writeFileSync(path.join(destination, 'empty'), '')
    expect(await hash(destination)).not.toBe(await hash(source))
  })

  it('rejects a stat failure even if it emitted partial metadata', async () => {
    const bin = path.join(root, 'bin')
    fs.mkdirSync(bin)
    fs.writeFileSync(
      path.join(bin, 'stat'),
      '#!/bin/sh\necho partial\nexit 23\n',
      {
        mode: 0o700
      }
    )
    await expect(
      localCalculateOutputHashSorted([
        'env',
        `PATH=${bin}:${process.env.PATH}`,
        'sh',
        '-c',
        listDirVerificationCommand(source)
      ])
    ).rejects.toThrow('child process exited with code')
  })
})
