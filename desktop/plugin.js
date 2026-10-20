// pka-solver — desktop half: a page in the sidebar plus a full workspace view.
//
// Loaded uncompiled, so no JSX: only jsx()/jsxs() from react/jsx-runtime, and
// only @hermes/plugin-sdk + react may be imported. All backend work goes
// through ctx.rest, which reaches dashboard/plugin_api.py next to the agent
// half — same handlers as the pka_inspect / pka_solve tools, so the two can
// never disagree.

import { host, ROUTES_AREA, SIDEBAR_NAV_AREA } from '@hermes/plugin-sdk'
import { jsx, jsxs } from 'react/jsx-runtime'
import { useCallback, useState } from 'react'

const PANEL_HINTS = {
  devices: 'perangkat',
  links: 'tautan',
  addresses: 'alamat',
  routing: 'routing',
  rubric: 'rubrik',
  report: 'laporan'
}

function Field({ label, hint, value, onChange, placeholder }) {
  return jsxs('div', {
    className: 'flex flex-col gap-1',
    children: [
      jsx('label', {
        className: 'text-[0.6875rem] text-(--ui-text-tertiary)',
        children: label
      }),
      jsx('input', {
        value: value,
        placeholder: placeholder || '',
        spellCheck: false,
        onChange: (e) => onChange(e.target.value),
        className:
          'rounded-md border border-(--ui-border) bg-(--ui-surface-raised) px-2 py-1.5 ' +
          'text-xs outline-none focus:border-(--ui-accent)'
      }),
      hint
        ? jsx('span', {
            className: 'text-[0.6875rem] text-(--ui-text-tertiary)',
            children: hint
          })
        : null
    ]
  })
}

function Stat({ label, value, tone }) {
  const color =
    tone === 'bad' ? 'text-(--ui-danger, #f87171)'
      : tone === 'good' ? 'text-(--ui-success, #4ade80)'
        : 'text-(--ui-text-primary)'
  return jsxs('div', {
    className: 'flex flex-col gap-0.5 rounded-lg border border-(--ui-border) px-2.5 py-2',
    children: [
      jsx('span', {
        className: 'text-[0.6875rem] text-(--ui-text-tertiary)',
        children: label
      }),
      jsx('span', { className: 'text-sm font-medium ' + color, children: String(value) })
    ]
  })
}

function RubricTable({ items }) {
  if (!items || !items.length) {
    return jsx('p', {
      className: 'text-xs text-(--ui-text-tertiary)',
      children: 'Tidak ada butir dinilai yang ditemukan.'
    })
  }
  return jsxs('div', {
    className: 'overflow-auto rounded-lg border border-(--ui-border)',
    children: [
      jsxs('table', {
        className: 'w-full border-collapse text-left text-xs',
        children: [
          jsx('thead', {
            className: 'bg-(--ui-surface-raised)',
            children: jsx('tr', {
              className: 'text-[0.6875rem] text-(--ui-text-tertiary)',
              children: [
                jsx('th', { className: 'px-2 py-1.5 font-medium', children: 'Poin' }),
                jsx('th', { className: 'px-2 py-1.5 font-medium', children: 'Butir' }),
                jsx('th', { className: 'px-2 py-1.5 font-medium', children: 'Harapan' })
              ]
            })
          }),
          jsx(
            'tbody',
            {},
            items.map((it, i) =>
              jsx('tr', {
                key: i,
                className: 'border-t border-(--ui-border) align-top',
                children: [
                  jsx('td', {
                    className: 'px-2 py-1.5 tabular-nums',
                    children: it.points || '—'
                  }),
                  jsx('td', { className: 'px-2 py-1.5', children: it.path }),
                  jsx('td', {
                    className: 'px-2 py-1.5 font-mono text-[0.6875rem]',
                    children: (it.expected || '—').slice(0, 80)
                  })
                ]
              })
            )
          )
        ]
      })
    ]
  })
}

function Panel() {
  const [path, setPath] = useState('')
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState(null)
  const [info, setInfo] = useState(null)
  const [solved, setSolved] = useState(null)
  const [converted, setConverted] = useState(null)

  const run = useCallback(
    async (label, fn) => {
      setBusy(label)
      setErr(null)
      try {
        const r = await fn()
        return r
      } catch (e) {
        setErr(String((e && e.message) || e))
        return null
      } finally {
        setBusy('')
      }
    },
    []
  )

  const onInspect = () =>
    run('inspect', async () => {
      if (!path.trim()) return
      const r = await ctxRest('inspect?path=' + encodeURIComponent(path.trim()))
      setInfo(r)
      setSolved(null)
    })

  const onSolve = () =>
    run('solve', async () => {
      if (!path.trim()) return
      const r = await ctxRestPost('/solve', { path: path.trim() })
      setSolved(r)
    })

  const onToXml = () =>
    run('to-xml', async () => {
      if (!path.trim()) return
      const r = await ctxRestPost('/to-xml', { path: path.trim() })
      setConverted(r)
    })

  return jsxs('div', {
    className: 'flex h-full flex-col gap-3 overflow-auto p-3 text-sm',
    children: [
      jsxs('div', {
        className: 'flex flex-col gap-2',
        children: [
          jsx('div', {
            className: 'text-xs font-medium text-(--ui-text-secondary)',
            children: 'Packet Tracer .pka'
          }),
          jsx(Field, {
            label: 'Path berkas',
            hint: 'Solve membaca answer key di blok 2, lalu tulis ulang jadi file 100%.',
            value: path,
            onChange: setPath,
            placeholder: 'C:/Users/you/Documents/soal.pka'
          })
        ]
      }),
      jsxs('div', {
        className: 'flex gap-2',
        children: [
          jsx('button', {
            type: 'button',
            disabled: busy !== '',
            onClick: onInspect,
            className:
              'rounded-md border border-(--ui-border) px-2.5 py-1.5 text-xs ' +
              'hover:bg-(--ui-surface-raised) disabled:opacity-50',
            children: busy === 'inspect' ? 'Membaca…' : 'Baca assessment'
          }),
          jsx('button', {
            type: 'button',
            disabled: busy !== '',
            onClick: onToXml,
            className:
              'rounded-md border border-(--ui-border) px-2.5 py-1.5 text-xs ' +
              'hover:bg-(--ui-surface-raised) disabled:opacity-50',
            children: busy === 'to-xml' ? 'Mengubah…' : 'PKA → XML'
          }),
          jsx('button', {
            type: 'button',
            disabled: busy !== '',
            onClick: onSolve,
            className:
              'rounded-md bg-(--ui-accent) px-2.5 py-1.5 text-xs font-medium ' +
              'text-(--ui-text-on-accent, #fff) disabled:opacity-50',
            children: busy === 'solve' ? 'Menyelesaikan…' : 'Selesaikan → 100%'
          })
        ]
      }),
      err
        ? jsxs('div', {
            className:
              'rounded-md border border-(--ui-danger, #f87171) px-2.5 py-2 ' +
              'text-xs text-(--ui-danger, #f87171)',
            children: err
          })
        : null,
      info ? Summary({ info }) : null,
      converted ? Converted({ converted }) : null,
      solved ? Solved({ solved }) : null
    ]
  })
}

function Summary({ info }) {
  const rows = [
    ['Versi PT', info.version],
    ['Blok', info.blocks],
    ['Perangkat', (info.starter_devices || []).length],
    ['Link', (info.answer_links || []).length],
    ['Answer key', info.answer_key_present ? 'ada' : 'TIDAK ADA'],
    ['Butir dinilai', info.rubric_items]
  ]
  return jsxs('div', {
    className: 'flex flex-col gap-3',
    children: [
      jsxs('div', {
        className: 'grid grid-cols-3 gap-1.5',
        children: rows.map(([k, v]) =>
          jsx(Stat, {
            key: k,
            label: k,
            value: v === undefined || v === null ? '—' : v,
            tone: k === 'Answer key' ? (info.answer_key_present ? 'good' : 'bad') : undefined
          })
        )
      }),
      info.instructions
        ? jsxs('div', {
            className: 'flex flex-col gap-1',
            children: [
              jsx('span', {
                className: 'text-[0.6875rem] text-(--ui-text-tertiary)',
                children: 'Instruksi'
              }),
              jsx('pre', {
                className:
                  'max-h-40 overflow-auto whitespace-pre-wrap rounded-lg border ' +
                  'border-(--ui-border) p-2 text-[0.6875rem]',
                children: info.instructions
              })
            ]
          })
        : null,
      info.addressing && info.addressing.length
        ? jsxs('div', {
            className: 'flex flex-col gap-1',
            children: [
              jsx('span', {
                className: 'text-[0.6875rem] text-(--ui-text-tertiary)',
                children: 'Alamat'
              }),
              jsx('div', {
                className: 'max-h-40 overflow-auto text-[0.6875rem]',
                children: info.addressing.map((a, i) =>
                  jsx('div', {
                    key: i,
                    className: 'font-mono',
                    children: `${a.device || ''} ${a.interface || ''} ${a.address || ''} ${a.mask || ''}`
                  })
                )
              })
            ]
          })
        : null,
      info.routing && info.routing.length
        ? jsxs('div', {
            className: 'flex flex-col gap-1',
            children: [
              jsx('span', {
                className: 'text-[0.6875rem] text-(--ui-text-tertiary)',
                children: 'Ringkasan routing'
              }),
              jsx('div', { className: 'max-h-40 overflow-auto text-[0.6875rem]', children:
                info.routing.map((r, i) =>
                  jsx('div', { key: i, className: 'font-mono', children:
                    `${r.device || ''}: ${r.summary || ''}` })
                )
              })
            ]
          })
        : null,
      jsxs('div', {
        className: 'flex flex-col gap-1',
        children: [
          jsx('span', {
            className: 'text-[0.6875rem] text-(--ui-text-tertiary)',
            children: `Rubrik assessment — ${info.rubric_items} butir dari ${info.rubric_total} node`
          }),
          jsx(RubricTable, { items: info.rubric })
        ]
      })
    ]
  })
}

function Converted({ converted }) {
  if (!converted.success) {
    return jsx('div', {
      className:
        'rounded-md border border-(--ui-danger, #f87171) px-2.5 py-2 ' +
        'text-xs text-(--ui-danger, #f87171)',
      children: converted.error || 'Gagal'
    })
  }
  return jsxs('div', {
    className:
      'flex flex-col gap-1 rounded-md border border-(--ui-border) ' +
      'px-2.5 py-2 text-xs',
    children: [
      jsx('div', {
        className: 'font-medium text-(--ui-text-secondary)',
        children: 'XML ditulis'
      }),
      jsx('div', {
        className: 'font-mono text-[0.6875rem] break-all',
        children: converted.output || '—'
      }),
      jsx('div', {
        className: 'text-(--ui-text-tertiary, var(--muted-foreground))',
        children:
          (converted.xml_bytes || 0).toLocaleString('id-ID') +
          ' byte · ' +
          (converted.blocks || 0) +
          ' blok · PT ' +
          (converted.pt_version || '?')
      })
    ]
  })
}

function Solved({ solved }) {
  if (!solved.success) {
    return jsx('div', {
      className: 'rounded-md border border-(--ui-danger, #f87171) px-2.5 py-2 text-xs',
      children: solved.error || 'Gagal.'
    })
  }
  const line = (k, v) =>
    jsxs('div', {
      key: k,
      className: 'flex justify-between gap-2 border-t border-(--ui-border) py-1 text-xs',
      children: [
        jsx('span', { className: 'text-(--ui-text-tertiary)', children: k }),
        jsx('span', { className: 'font-mono text-[0.6875rem]', children: String(v) })
      ]
    })
  return jsxs('div', {
    className: 'flex flex-col gap-2',
    children: [
      jsxs('div', {
        className: 'flex flex-col gap-1 rounded-lg border border-(--ui-success, #4ade80) p-2.5',
        children: [
          jsx('span', {
            className: 'text-xs font-medium text-(--ui-success, #4ade80)',
            children: 'Selesai — file siap dibuka di Packet Tracer'
          }),
          line('output', solved.output),
          line('perangkat', solved.devices),
          line('interface di-up', solved.interfaces_brought_up),
          line('roundtrip', solved.roundtrip_verified ? 'terverifikasi' : 'GAGAL')
        ]
      }),
      solved.report_text
        ? jsxs('div', {
            className: 'flex flex-col gap-1',
            children: [
              jsx('span', {
                className: 'text-[0.6875rem] text-(--ui-text-tertiary)',
                children: 'Laporan'
              }),
              jsx('pre', {
                className:
                  'max-h-64 overflow-auto whitespace-pre-wrap rounded-lg border ' +
                  'border-(--ui-border) p-2 text-[0.6875rem]',
                children: solved.report_text
              })
            ]
          })
        : null
    ]
  })
}

// ctx.rest is injected by the host per registration; these thin wrappers keep
// the query-string and body shapes in one place.
let _rest = (path, opts) => {
  throw new Error('pka-solver: backend not registered yet')
}
const ctxRest = (path, opts) => _rest(path, opts)
// The desktop fetch layer defaults to a 15s timeout; a large .pka takes
// several seconds to decrypt, so these long calls raise it explicitly rather
// than relying on the default holding.
const ctxRestPost = (path, body) =>
  _rest(path, { method: 'POST', body, timeoutMs: 300000 })

export default {
  id: 'pka-solver',
  name: 'PKA Solver',
  // Registers on load: the user installed it deliberately and the panel only
  // reads files under the coursework roots the backend allowlists. Flip to
  // false if it should instead inventory disabled until toggled in
  // Capabilities → Plugins.
  defaultEnabled: true,
  register(ctx) {
    _rest = ctx.rest
    ctx.registerMany([
      {
        id: 'page',
        area: ROUTES_AREA,
        data: { path: '/pka-solver' },
        render: () => jsx(Panel, {})
      },
      {
        id: 'nav',
        area: SIDEBAR_NAV_AREA,
        order: 60,
        data: { path: '/pka-solver', label: 'PKA Solver', codicon: 'circuit-board' }
      }
    ])
  }
}