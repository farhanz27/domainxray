<script setup>
import { ref, computed, onMounted } from 'vue'

const DEFAULT_DNS_HINT = '8.8.8.8'
const RESOLVER_PLACEHOLDER = 'Defaults to 8.8.8.8'
const MAX_GEO_IPS = 6
const BULK_LIMIT = 20

// ── Core state ──────────────────────────────────────────────────────────────
const domain   = ref('')
const resolver = ref('')
const resolverError = ref('')
const mode    = ref('full')
const loading = ref(false)
const error   = ref('')
const result  = ref(null)

// ── Supplementary async state ────────────────────────────────────────────────
const ssl        = ref(null)
const sslLoading = ref(false)
const geo        = ref({})
const geoLoading = ref(false)
const dmarc      = ref(null)

// ── UI state ─────────────────────────────────────────────────────────────────
const showRaw    = ref(false)
const copiedKey  = ref('')

// ── Bulk state ────────────────────────────────────────────────────────────────
const bulkInput   = ref('')
const bulkResults = ref([])
const bulkLoading = ref(false)

// ── Compare state ─────────────────────────────────────────────────────────────
const cmpD1  = ref('')
const cmpD2  = ref('')
const cmpR1  = ref(null)
const cmpR2  = ref(null)
const cmpLoading = ref(false)

// ── Constants ─────────────────────────────────────────────────────────────────
const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'PTR', 'SRV', 'CAA']
const recordColors = {
  A:    'bg-blue-500/10 text-blue-400 border-blue-500/20',
  AAAA: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  CNAME:'bg-amber-500/10 text-amber-400 border-amber-500/20',
  MX:   'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  NS:   'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  TXT:  'bg-rose-500/10 text-rose-400 border-rose-500/20',
  PTR:  'bg-orange-500/10 text-orange-400 border-orange-500/20',
  SRV:  'bg-pink-500/10 text-pink-400 border-pink-500/20',
  CAA:  'bg-violet-500/10 text-violet-400 border-violet-500/20',
}
const whoisFields = [
  { key: 'registrar',       label: 'Registrar' },
  { key: 'whois_server',    label: 'WHOIS Server' },
  { key: 'creation_date',   label: 'Created' },
  { key: 'expiration_date', label: 'Expires' },
  { key: 'updated_date',    label: 'Updated' },
]

// ── Computed ──────────────────────────────────────────────────────────────────
const dnsData = computed(() => {
  if (!result.value) return null
  return result.value.dns ?? result.value
})
const whoisData = computed(() => {
  if (!result.value) return null
  return result.value.whois ?? result.value
})
const domainError = computed(() => {
  if (!result.value) return null
  const dns   = result.value.dns   ?? result.value
  const whois = result.value.whois ?? result.value
  if (dns?.error && whois?.error) return dns.error
  return null
})
const bulkDomainCount = computed(() =>
  bulkInput.value.split(/[\n,]+/).filter(d => d.trim()).length
)
const emailSec = computed(() => {
  const txts = (dnsData.value?.records?.TXT || []).map(r => r.value)
  const spf  = txts.find(r => r.toLowerCase().startsWith('v=spf1')) || null
  let dmarcRec = null
  if (dmarc.value?.records?.TXT?.length) {
    dmarcRec = dmarc.value.records.TXT.find(r => r.value.toLowerCase().startsWith('v=dmarc1'))?.value || null
  }
  return { spf, dmarc: dmarcRec }
})
const dnssecStatus = computed(() => {
  const val = whoisData.value?.dnssec
  if (!val) return null
  const lower = val.toLowerCase()
  if (lower.includes('signed') || lower === 'yes' || lower === 'true')
    return { label: val, ok: true }
  return { label: val, ok: false }
})
const health = computed(() => {
  if (!result.value || domainError.value) return null
  const checks = []
  if (dnsData.value) {
    const ok = !dnsData.value.error && Object.keys(dnsData.value.records || {}).length > 0
    checks.push({ label: 'DNS resolves', pass: ok, warn: false })
  }
  if (whoisData.value && !whoisData.value.error && whoisData.value.expiration_date) {
    const days = Math.round((new Date(whoisData.value.expiration_date) - Date.now()) / 86400000)
    checks.push({ label: 'Domain expiry', pass: days > 30, warn: days > 0 && days <= 30, detail: `${days}d` })
  }
  if (ssl.value) {
    if (ssl.value.error) {
      checks.push({ label: 'SSL certificate', pass: false, warn: false, detail: ssl.value.error })
    } else {
      const warn = ssl.value.days_until_expiry <= 30
      checks.push({ label: 'SSL certificate', pass: ssl.value.valid, warn, detail: warn ? `${ssl.value.days_until_expiry}d` : null })
    }
  }
  if (mode.value !== 'whois' && dnsData.value && !dnsData.value.error) {
    checks.push({ label: 'SPF record',   pass: !!emailSec.value.spf,   warn: false })
    checks.push({ label: 'DMARC record', pass: !!emailSec.value.dmarc, warn: false })
  }
  const passed = checks.filter(c => c.pass).length
  const score  = checks.length ? Math.round((passed / checks.length) * 100) : 0
  const color  = score >= 80 ? 'text-emerald-400' : score >= 50 ? 'text-amber-400' : 'text-red-400'
  const bar    = score >= 80 ? 'bg-emerald-500'   : score >= 50 ? 'bg-amber-500'   : 'bg-red-500'
  const ring   = score >= 80 ? 'border-emerald-500/30' : score >= 50 ? 'border-amber-500/30' : 'border-red-500/30'
  return { checks, passed, total: checks.length, score, color, bar, ring }
})

// ── Mode switch ───────────────────────────────────────────────────────────────
function switchMode(m) {
  mode.value  = m
  error.value = ''
  if (['bulk', 'compare'].includes(m)) {
    result.value = null; ssl.value = null; geo.value = {}; dmarc.value = null
  } else {
    bulkResults.value = []; cmpR1.value = null; cmpR2.value = null
  }
}

// ── URL param sync ────────────────────────────────────────────────────────────
function syncUrl() {
  const p = new URLSearchParams()
  const d = domain.value.trim()
  if (d) p.set('domain', d)
  if (mode.value !== 'full') p.set('mode', mode.value)
  window.history.replaceState({}, '', p.toString() ? `?${p}` : window.location.pathname)
}

onMounted(() => {
  const p = new URLSearchParams(window.location.search)
  const d = p.get('domain'), m = p.get('mode')
  if (m && ['full','dns','whois'].includes(m)) mode.value = m
  if (d) { domain.value = d; lookup() }
})

// ── Clipboard ─────────────────────────────────────────────────────────────────
async function copy(text, key) {
  try {
    await navigator.clipboard.writeText(text)
    copiedKey.value = key
    setTimeout(() => { copiedKey.value = '' }, 2000)
  } catch {}
}

// ── Validation ────────────────────────────────────────────────────────────────
function validateResolver(value) {
  const t = value.trim()
  if (!t) { resolverError.value = ''; return true }
  let s = t
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1)
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s) && s.split('.').map(Number).every(n => n >= 0 && n <= 255)) {
    resolverError.value = ''; return true
  }
  if (s.includes(':') && /^[0-9a-f:.]+$/i.test(s)) { resolverError.value = ''; return true }
  resolverError.value = 'Enter a valid IPv4 or IPv6 address (e.g. 1.1.1.1 or 2606:4700:4700::1111).'
  return false
}
function formatApiError(body, status) {
  if (!body?.detail) return `Request failed (${status})`
  const d = body.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d)) return d.map(e => e.msg || JSON.stringify(e)).join(' ')
  return String(d)
}

// ── Main lookup ───────────────────────────────────────────────────────────────
async function lookup() {
  const d = domain.value.trim()
  if (!d) return
  if (mode.value !== 'whois' && !validateResolver(resolver.value)) {
    error.value = ''; result.value = null; return
  }
  loading.value = true; error.value = ''; result.value = null
  ssl.value = null; geo.value = {}; dmarc.value = null; showRaw.value = false
  syncUrl()
  const r = resolver.value.trim()
  const rp = r ? `&resolver=${encodeURIComponent(r)}` : ''
  const endpoints = {
    full:  `/api/inspect?domain=${encodeURIComponent(d)}${rp}`,
    dns:   `/api/dns?domain=${encodeURIComponent(d)}${rp}`,
    whois: `/api/whois?domain=${encodeURIComponent(d)}`,
  }
  try {
    const res = await fetch(endpoints[mode.value])
    if (!res.ok) { const b = await res.json().catch(() => null); throw new Error(formatApiError(b, res.status)) }
    result.value = await res.json()
  } catch (e) { error.value = e.message } finally { loading.value = false }
  if (result.value && !domainError.value && mode.value !== 'whois') {
    fetchSsl(d); fetchGeo(); fetchDmarc(d)
  }
}
function onKey(e) { if (e.key === 'Enter') lookup() }
function clearDomain() { domain.value = ''; result.value = null; error.value = '' }

// ── SSL ───────────────────────────────────────────────────────────────────────
async function fetchSsl(d) {
  sslLoading.value = true
  try { const res = await fetch(`/api/ssl?domain=${encodeURIComponent(d)}`); ssl.value = await res.json() }
  catch {} finally { sslLoading.value = false }
}

// ── Geolocation ───────────────────────────────────────────────────────────────
function flagEmoji(code) {
  if (!code || code.length !== 2) return ''
  return [...code.toUpperCase()].map(c => String.fromCodePoint(0x1F1E6 + c.charCodeAt(0) - 65)).join('')
}
async function fetchGeo() {
  const ips = [
    ...(dnsData.value?.records?.A    || []).map(r => r.value),
    ...(dnsData.value?.records?.AAAA || []).map(r => r.value),
  ].slice(0, MAX_GEO_IPS)
  if (!ips.length) return
  geoLoading.value = true
  try {
    const results = await Promise.allSettled(ips.map(ip => fetch(`https://ipwho.is/${ip}`).then(r => r.json())))
    const map = {}
    results.forEach((r, i) => {
      if (r.status === 'fulfilled' && r.value?.success)
        map[ips[i]] = { country: r.value.country, city: r.value.city, flag: flagEmoji(r.value.country_code) }
    })
    geo.value = map
  } catch {} finally { geoLoading.value = false }
}

// ── DMARC ─────────────────────────────────────────────────────────────────────
async function fetchDmarc(d) {
  try {
    const res = await fetch(`/api/dns?domain=${encodeURIComponent('_dmarc.' + d)}&types=TXT`)
    if (res.ok) dmarc.value = await res.json()
  } catch {}
}

// ── Bulk scan ─────────────────────────────────────────────────────────────────
async function runBulk() {
  const list = bulkInput.value.split(/[\n,]+/).map(d => d.trim()).filter(Boolean)
  if (!list.length) return
  bulkLoading.value = true; bulkResults.value = []; error.value = ''
  try {
    const r = resolver.value.trim()
    const rp = r ? `&resolver=${encodeURIComponent(r)}` : ''
    const res = await fetch(`/api/bulk?domains=${encodeURIComponent(list.join(','))}${rp}`)
    if (!res.ok) { const b = await res.json().catch(() => null); throw new Error(formatApiError(b, res.status)) }
    bulkResults.value = await res.json()
  } catch (e) { error.value = e.message } finally { bulkLoading.value = false }
}
function clearBulk() { bulkInput.value = ''; bulkResults.value = []; error.value = '' }

function bulkDnsOk(item) {
  const dns = item.dns ?? item
  return !dns?.error && Object.keys(dns?.records || {}).length > 0
}
function bulkWhoisExp(item) { return (item.whois ?? item)?.expiration_date || null }
function bulkExpClass(item) {
  const exp = bulkWhoisExp(item)
  if (!exp) return 'text-gray-600'
  const days = (new Date(exp) - Date.now()) / 86400000
  return days < 30 ? 'text-red-400' : days < 90 ? 'text-amber-400' : 'text-emerald-400'
}
function bulkSpf(item) {
  return (((item.dns ?? item)?.records?.TXT) || []).some(r => r.value.toLowerCase().startsWith('v=spf1'))
}

// ── Compare ───────────────────────────────────────────────────────────────────
async function runCompare() {
  const d1 = cmpD1.value.trim(), d2 = cmpD2.value.trim()
  if (!d1 || !d2) return
  cmpLoading.value = true; cmpR1.value = null; cmpR2.value = null; error.value = ''
  try {
    const r = resolver.value.trim(), rp = r ? `&resolver=${encodeURIComponent(r)}` : ''
    const [r1, r2] = await Promise.all([
      fetch(`/api/inspect?domain=${encodeURIComponent(d1)}${rp}`).then(x => x.json()),
      fetch(`/api/inspect?domain=${encodeURIComponent(d2)}${rp}`).then(x => x.json()),
    ])
    cmpR1.value = r1; cmpR2.value = r2
  } catch (e) { error.value = e.message } finally { cmpLoading.value = false }
}
function clearCompare() { cmpD1.value = ''; cmpD2.value = ''; cmpR1.value = null; cmpR2.value = null }
function cmpRecords(result, type) { return (result?.dns ?? result)?.records?.[type] || [] }
function cmpWhoisField(result, key) { return (result?.whois ?? result)?.[key] || '—' }
</script>

<template>
  <div class="min-h-screen bg-gray-950 text-gray-100">

    <!-- ── Header ────────────────────────────────────────────────────────── -->
    <header class="border-b border-gray-800/60 bg-gray-950/80 backdrop-blur-sm sticky top-0 z-10">
      <div class="max-w-5xl mx-auto px-4 sm:px-6 py-4 flex items-center gap-3">
        <div class="size-8 rounded-lg bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center shrink-0">
          <svg class="size-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"/>
          </svg>
        </div>
        <div>
          <h1 class="text-sm font-semibold tracking-tight leading-none">DomainXray</h1>
          <p class="text-[11px] text-gray-500 mt-0.5">DNS &amp; WHOIS Analysis</p>
        </div>
      </div>
    </header>

    <main class="max-w-5xl mx-auto px-4 sm:px-6 py-8 space-y-6">

      <!-- ── Mode tabs ──────────────────────────────────────────────────── -->
      <div class="flex items-center gap-1.5">
        <!-- Single-domain tabs -->
        <div class="flex gap-0.5 bg-gray-900 border border-gray-800/60 rounded-lg p-0.5">
          <button v-for="m in [{id:'full',label:'Full Scan'},{id:'dns',label:'DNS'},{id:'whois',label:'WHOIS'}]"
            :key="m.id" @click="switchMode(m.id)"
            :class="['px-3.5 py-1.5 rounded-md text-xs font-medium transition-all',
              mode === m.id ? 'bg-gray-800 text-gray-100 shadow-sm' : 'text-gray-500 hover:text-gray-300']">
            {{ m.label }}
          </button>
        </div>
        <!-- Divider -->
        <div class="w-px h-5 bg-gray-800 mx-0.5"/>
        <!-- Multi-domain tabs -->
        <div class="flex gap-0.5 bg-gray-900 border border-gray-800/60 rounded-lg p-0.5">
          <button v-for="m in [{id:'bulk',label:'Bulk'},{id:'compare',label:'Compare'}]"
            :key="m.id" @click="switchMode(m.id)"
            :class="['px-3.5 py-1.5 rounded-md text-xs font-medium transition-all',
              mode === m.id ? 'bg-gray-800 text-gray-100 shadow-sm' : 'text-gray-500 hover:text-gray-300']">
            {{ m.label }}
          </button>
        </div>
      </div>

      <!-- ── Single-domain input ────────────────────────────────────────── -->
      <div v-if="!['bulk','compare'].includes(mode)" class="space-y-3">
        <!-- Input row -->
        <div class="flex gap-2">
          <div class="relative flex-1">
            <input v-model="domain" @keydown="onKey" type="text"
              placeholder="Enter domain name (e.g. google.com)"
              class="w-full bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 pr-10 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-violet-600/70 focus:ring-1 focus:ring-violet-600/40 transition-colors"/>
            <button v-if="domain" @click="clearDomain"
              class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-300 transition-colors">
              <svg class="size-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
              </svg>
            </button>
          </div>
          <button @click="lookup"
            :disabled="loading || !domain.trim() || (mode !== 'whois' && !!resolverError)"
            class="px-5 py-3 bg-violet-600 hover:bg-violet-500 active:bg-violet-700 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg text-sm font-medium transition-colors shrink-0 inline-flex items-center gap-2">
            <svg v-if="!loading" class="size-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"/>
            </svg>
            <svg v-else class="animate-spin size-4" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
            {{ loading ? 'Scanning…' : 'Scan' }}
          </button>
        </div>

        <!-- Examples + Resolver row -->
        <div class="flex flex-col gap-2.5 sm:flex-row sm:items-start sm:justify-between">
          <div class="flex flex-wrap gap-1.5">
            <span class="text-[11px] text-gray-600 self-center mr-0.5">Try:</span>
            <button v-for="ex in ['github.com', 'cloudflare.com', 'google.com']" :key="ex"
              @click="domain = ex; lookup()"
              class="text-xs bg-gray-900 border border-gray-800 hover:border-gray-700 hover:bg-gray-800/50 text-gray-500 hover:text-gray-300 rounded-full px-2.5 py-1 transition-all">
              {{ ex }}
            </button>
          </div>

          <!-- Custom resolver -->
          <div v-show="mode !== 'whois'" class="flex flex-col gap-1 sm:items-end shrink-0">
            <div class="flex items-center gap-2">
              <label for="resolver-input" class="text-xs text-gray-500 shrink-0">Resolver</label>
              <div class="relative w-44">
                <input id="resolver-input" v-model="resolver" type="text"
                  autocomplete="off" spellcheck="false" :placeholder="RESOLVER_PLACEHOLDER"
                  :class="['w-full h-8 rounded-lg border bg-gray-900 px-2.5 pr-7 text-xs font-mono text-gray-300 placeholder:text-gray-600 outline-none transition-[border-color,box-shadow]',
                    resolverError ? 'border-red-500/50 focus:border-red-500/60 focus:ring-1 focus:ring-red-500/20'
                                  : 'border-gray-800 focus:border-violet-600/50 focus:ring-1 focus:ring-violet-600/20']"
                  @input="e => { validateResolver(e.target.value); if (!resolverError) error = '' }"
                  @keydown="onKey"/>
                <button v-if="resolver.trim()" @click="resolver=''; resolverError=''"
                  class="absolute right-1.5 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-400 transition-colors">
                  <svg class="size-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
                  </svg>
                </button>
              </div>
            </div>
            <p v-if="resolverError" class="text-[11px] text-red-400/90 text-right">{{ resolverError }}</p>
          </div>
        </div>
      </div>

      <!-- ── Bulk input ──────────────────────────────────────────────────── -->
      <div v-if="mode === 'bulk'" class="space-y-3">
        <div class="flex items-center justify-between mb-1">
          <p class="text-xs text-gray-500">One domain per line, or comma-separated</p>
          <span :class="['text-xs font-mono tabular-nums',
            bulkDomainCount > BULK_LIMIT ? 'text-red-400' : bulkDomainCount > 0 ? 'text-gray-400' : 'text-gray-600']">
            {{ bulkDomainCount }} / {{ BULK_LIMIT }}
          </span>
        </div>
        <textarea v-model="bulkInput" rows="6"
          placeholder="google.com&#10;cloudflare.com&#10;github.com"
          class="w-full bg-gray-900 border border-gray-800 rounded-xl px-4 py-3 text-sm text-gray-200 placeholder-gray-700 focus:outline-none focus:border-violet-600/70 focus:ring-1 focus:ring-violet-600/40 transition-colors resize-y font-mono leading-relaxed"/>
        <div class="flex items-center gap-2">
          <button @click="runBulk"
            :disabled="bulkLoading || !bulkInput.trim() || bulkDomainCount > BULK_LIMIT"
            class="px-4 py-2 bg-violet-600 hover:bg-violet-500 active:bg-violet-700 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg text-sm font-medium transition-colors inline-flex items-center gap-2">
            <svg v-if="!bulkLoading" class="size-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z"/>
            </svg>
            <svg v-else class="animate-spin size-4" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
            {{ bulkLoading ? 'Scanning…' : 'Scan All' }}
          </button>
          <button @click="clearBulk" :disabled="!bulkInput && !bulkResults.length"
            class="px-4 py-2 border border-gray-700 hover:border-gray-600 hover:bg-gray-800 disabled:opacity-30 disabled:cursor-not-allowed text-gray-400 hover:text-gray-200 rounded-lg text-sm font-medium transition-colors inline-flex items-center gap-2">
            <svg class="size-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
            </svg>
            Clear
          </button>
        </div>
      </div>

      <!-- ── Compare input ──────────────────────────────────────────────── -->
      <div v-if="mode === 'compare'" class="space-y-3">
        <div class="flex items-center gap-3">
          <div class="relative flex-1">
            <input v-model="cmpD1" @keydown="e => e.key==='Enter' && runCompare()" type="text"
              placeholder="First domain (e.g. google.com)"
              class="w-full bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 pr-10 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-violet-600/70 focus:ring-1 focus:ring-violet-600/40 transition-colors"/>
            <button v-if="cmpD1" @click="cmpD1 = ''; cmpR1 = null"
              class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-300 transition-colors">
              <svg class="size-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
              </svg>
            </button>
          </div>
          <span class="text-xs text-gray-600 font-medium shrink-0 px-1">vs</span>
          <div class="relative flex-1">
            <input v-model="cmpD2" @keydown="e => e.key==='Enter' && runCompare()" type="text"
              placeholder="Second domain (e.g. cloudflare.com)"
              class="w-full bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 pr-10 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-violet-600/70 focus:ring-1 focus:ring-violet-600/40 transition-colors"/>
            <button v-if="cmpD2" @click="cmpD2 = ''; cmpR2 = null"
              class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-300 transition-colors">
              <svg class="size-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
              </svg>
            </button>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <button @click="runCompare" :disabled="cmpLoading || !cmpD1.trim() || !cmpD2.trim()"
            class="px-4 py-2 bg-violet-600 hover:bg-violet-500 active:bg-violet-700 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg text-sm font-medium transition-colors inline-flex items-center gap-2">
            <svg v-if="!cmpLoading" class="size-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5"/>
            </svg>
            <svg v-else class="animate-spin size-4" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
            {{ cmpLoading ? 'Comparing…' : 'Compare' }}
          </button>
          <button v-if="cmpR1 || cmpR2 || cmpD1 || cmpD2" @click="clearCompare"
            class="px-4 py-2 border border-gray-700 hover:border-gray-600 hover:bg-gray-800 text-gray-400 hover:text-gray-200 rounded-lg text-sm font-medium transition-colors inline-flex items-center gap-2">
            <svg class="size-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
            </svg>
            Clear
          </button>
        </div>
      </div>

      <!-- ── Global error ────────────────────────────────────────────────── -->
      <div v-if="error" class="bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 text-sm text-red-400 flex items-start gap-3">
        <svg class="size-4 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"/>
        </svg>
        {{ error }}
      </div>

      <!-- ── Domain-level error ──────────────────────────────────────────── -->
      <div v-if="result && domainError" class="bg-red-500/10 border border-red-500/20 rounded-xl px-5 py-8 text-center">
        <svg class="size-8 text-red-400 mx-auto mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"/>
        </svg>
        <p class="text-sm font-medium text-red-400">{{ domainError }}</p>
      </div>

      <!-- ╔══════════════════════════════════════════════════════════════════╗ -->
      <!-- ║  SINGLE DOMAIN RESULTS                                          ║ -->
      <!-- ╚══════════════════════════════════════════════════════════════════╝ -->
      <div v-if="result && !domainError && !['bulk','compare'].includes(mode)" class="space-y-4">

        <!-- ── Health score ────────────────────────────────────────────── -->
        <div v-if="health && health.total" class="bg-gray-900/60 border rounded-xl p-5" :class="health.ring">
          <div class="flex items-center justify-between mb-3">
            <div class="flex items-center gap-2">
              <svg class="size-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>
              </svg>
              <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400">Domain Health</h2>
            </div>
            <span class="text-xl font-bold tabular-nums" :class="health.color">{{ health.score }}%</span>
          </div>
          <!-- Progress bar -->
          <div class="h-1 bg-gray-800 rounded-full mb-4 overflow-hidden">
            <div class="h-full rounded-full transition-all duration-700" :class="health.bar" :style="`width:${health.score}%`"/>
          </div>
          <!-- Check grid -->
          <div class="grid grid-cols-2 sm:grid-cols-3 gap-2">
            <div v-for="c in health.checks" :key="c.label"
              class="flex items-center gap-2 rounded-lg px-3 py-2 text-xs"
              :class="c.pass ? 'bg-emerald-500/10 text-emerald-300' : c.warn ? 'bg-amber-500/10 text-amber-300' : 'bg-red-500/10 text-red-300'">
              <svg v-if="c.pass" class="size-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/>
              </svg>
              <svg v-else-if="c.warn" class="size-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z"/>
              </svg>
              <svg v-else class="size-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
              </svg>
              <span class="truncate">{{ c.label }}<span v-if="c.detail" class="opacity-60 ml-1">({{ c.detail }})</span></span>
            </div>
          </div>
        </div>

        <!-- ── DNS Records ─────────────────────────────────────────────── -->
        <section v-if="mode !== 'whois' && dnsData" class="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
          <div class="px-5 py-3.5 border-b border-gray-800/60 flex items-center gap-3">
            <svg class="size-4 text-gray-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5a17.92 17.92 0 01-8.716-2.247m0 0A9 9 0 013 12c0-1.328.288-2.584.804-3.718"/>
            </svg>
            <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400 flex-1">DNS Records</h2>
            <span class="text-[11px] text-gray-700 font-mono">{{ dnsData.resolver }}</span>
            <!-- Copy button -->
            <button @click="copy(JSON.stringify(dnsData.records, null, 2), 'dns')" title="Copy as JSON"
              class="p-1.5 rounded-md text-gray-600 hover:text-gray-300 hover:bg-gray-800 transition-colors">
              <svg v-if="copiedKey !== 'dns'" class="size-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184"/>
              </svg>
              <svg v-else class="size-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/>
              </svg>
            </button>
          </div>
          <div v-if="dnsData.error" class="px-5 py-8 text-center text-sm text-red-400">{{ dnsData.error }}</div>
          <div v-else-if="!Object.keys(dnsData.records).length" class="px-5 py-8 text-center text-sm text-gray-600">No DNS records found.</div>
          <div v-else class="divide-y divide-gray-800/40">
            <div v-for="rtype in recordTypes" :key="rtype">
              <div v-if="dnsData.records[rtype]" class="px-5 py-4">
                <div class="flex items-center gap-2 mb-2.5">
                  <span :class="['text-xs font-bold px-2 py-0.5 rounded border', recordColors[rtype] || 'bg-gray-800 text-gray-400']">{{ rtype }}</span>
                  <span class="text-xs text-gray-700">{{ dnsData.records[rtype].length }} record{{ dnsData.records[rtype].length > 1 ? 's' : '' }}</span>
                </div>
                <div class="space-y-1.5">
                  <div v-for="(rec, i) in dnsData.records[rtype]" :key="i"
                    class="flex items-center gap-2 text-sm font-mono flex-wrap">
                    <span class="text-gray-200 break-all">{{ rec.value }}</span>
                    <span v-if="rec.priority != null" class="text-xs text-amber-500/70 bg-amber-500/10 px-1.5 rounded">pri {{ rec.priority }}</span>
                    <span v-if="(rtype === 'A' || rtype === 'AAAA') && geo[rec.value]"
                      class="text-[11px] text-gray-500 bg-gray-800/80 rounded-full px-2 py-0.5 inline-flex items-center gap-1">
                      {{ geo[rec.value].flag }} {{ geo[rec.value].city }}, {{ geo[rec.value].country }}
                    </span>
                    <span class="text-[11px] text-gray-700 ml-auto shrink-0">TTL {{ rec.ttl }}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div v-if="Object.keys(dnsData.errors || {}).length" class="px-5 py-3 border-t border-gray-800/60 space-y-1">
            <div v-for="(err, rtype) in dnsData.errors" :key="rtype" class="text-xs text-red-400/80">
              <span class="font-semibold">{{ rtype }}:</span> {{ err }}
            </div>
          </div>
        </section>

        <!-- ── SSL Certificate ─────────────────────────────────────────── -->
        <section v-if="mode !== 'whois'" class="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
          <div class="px-5 py-3.5 border-b border-gray-800/60 flex items-center gap-3">
            <svg class="size-4 text-gray-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75">
              <path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"/>
            </svg>
            <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400 flex-1">SSL Certificate</h2>
            <svg v-if="sslLoading" class="animate-spin size-3.5 text-gray-600" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
            <!-- Valid badge -->
            <span v-if="ssl && !ssl.error" :class="['text-xs px-2 py-0.5 rounded-full font-medium',
              ssl.valid ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400']">
              {{ ssl.valid ? 'Valid' : 'Expired' }}
            </span>
          </div>
          <div v-if="!ssl && !sslLoading" class="px-5 py-4 text-xs text-gray-600 italic">Checking…</div>
          <div v-else-if="ssl?.error" class="px-5 py-4 text-sm text-red-400/80 flex items-center gap-2">
            <svg class="size-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
            </svg>
            {{ ssl.error }}
          </div>
          <div v-else-if="ssl" class="px-5 py-4 grid grid-cols-2 gap-x-8 gap-y-4">
            <div class="flex flex-col gap-0.5">
              <span class="text-[11px] text-gray-600 uppercase tracking-wider">Common Name</span>
              <span class="text-sm text-gray-200 font-mono">{{ ssl.common_name }}</span>
            </div>
            <div class="flex flex-col gap-0.5">
              <span class="text-[11px] text-gray-600 uppercase tracking-wider">Issuer</span>
              <span class="text-sm text-gray-300">{{ ssl.issuer }}</span>
            </div>
            <div class="flex flex-col gap-0.5">
              <span class="text-[11px] text-gray-600 uppercase tracking-wider">Issued</span>
              <span class="text-sm text-gray-300 font-mono">{{ ssl.issued }}</span>
            </div>
            <div class="flex flex-col gap-0.5">
              <span class="text-[11px] text-gray-600 uppercase tracking-wider">Expires</span>
              <span class="text-sm font-mono" :class="ssl.days_until_expiry <= 0 ? 'text-red-400' : ssl.days_until_expiry <= 30 ? 'text-amber-400' : 'text-gray-300'">
                {{ ssl.expires }}
                <span class="text-[11px] opacity-60 ml-1">({{ ssl.days_until_expiry }}d)</span>
              </span>
            </div>
            <div v-if="ssl.san?.length" class="flex flex-col gap-1.5 col-span-2">
              <span class="text-[11px] text-gray-600 uppercase tracking-wider">Subject Alt Names</span>
              <div class="flex flex-wrap gap-1.5">
                <span v-for="s in ssl.san" :key="s"
                  class="text-xs font-mono bg-gray-800/80 text-gray-400 border border-gray-700/50 px-2 py-0.5 rounded">{{ s }}</span>
              </div>
            </div>
          </div>
        </section>

        <!-- ── Email Security ──────────────────────────────────────────── -->
        <section v-if="mode !== 'whois' && dnsData && !dnsData.error" class="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
          <div class="px-5 py-3.5 border-b border-gray-800/60 flex items-center gap-3">
            <svg class="size-4 text-gray-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75">
              <path stroke-linecap="round" stroke-linejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75"/>
            </svg>
            <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400">Email Security</h2>
          </div>
          <div class="divide-y divide-gray-800/40">
            <div class="px-5 py-4 flex items-start gap-4">
              <div class="flex flex-col gap-1.5 w-16 shrink-0">
                <span class="text-xs font-bold text-gray-500 uppercase tracking-wider">SPF</span>
                <span :class="['text-[11px] px-2 py-0.5 rounded-full font-medium text-center',
                  emailSec.spf ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400']">
                  {{ emailSec.spf ? 'Found' : 'Missing' }}
                </span>
              </div>
              <div class="flex-1 min-w-0">
                <p v-if="emailSec.spf" class="text-xs font-mono text-gray-400 break-all leading-relaxed">{{ emailSec.spf }}</p>
                <p v-else class="text-xs text-gray-600">No SPF record — senders can spoof this domain.</p>
              </div>
            </div>
            <div class="px-5 py-4 flex items-start gap-4">
              <div class="flex flex-col gap-1.5 w-16 shrink-0">
                <span class="text-xs font-bold text-gray-500 uppercase tracking-wider">DMARC</span>
                <span :class="['text-[11px] px-2 py-0.5 rounded-full font-medium text-center',
                  emailSec.dmarc ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400']">
                  {{ emailSec.dmarc ? 'Found' : 'Missing' }}
                </span>
              </div>
              <div class="flex-1 min-w-0">
                <p v-if="emailSec.dmarc" class="text-xs font-mono text-gray-400 break-all leading-relaxed">{{ emailSec.dmarc }}</p>
                <p v-else class="text-xs text-gray-600">No DMARC at _dmarc.{{ domain.trim() }} — no policy enforcement.</p>
              </div>
            </div>
          </div>
        </section>

        <!-- ── WHOIS ───────────────────────────────────────────────────── -->
        <section v-if="mode !== 'dns' && whoisData" class="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
          <div class="px-5 py-3.5 border-b border-gray-800/60 flex items-center gap-3">
            <svg class="size-4 text-gray-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75">
              <path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z"/>
            </svg>
            <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400 flex-1">WHOIS</h2>
            <!-- Raw / Structured toggle -->
            <button v-if="whoisData.raw_text" @click="showRaw = !showRaw"
              class="text-[11px] px-2.5 py-1 border border-gray-700 hover:border-gray-600 rounded-md text-gray-500 hover:text-gray-300 transition-colors font-medium">
              {{ showRaw ? 'Structured' : 'Raw' }}
            </button>
            <!-- Copy -->
            <button @click="copy(JSON.stringify(whoisData, null, 2), 'whois')" title="Copy as JSON"
              class="p-1.5 rounded-md text-gray-600 hover:text-gray-300 hover:bg-gray-800 transition-colors">
              <svg v-if="copiedKey !== 'whois'" class="size-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184"/>
              </svg>
              <svg v-else class="size-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/>
              </svg>
            </button>
          </div>

          <div v-if="whoisData.error" class="px-5 py-4 text-sm text-red-400/80">{{ whoisData.error }}</div>
          <div v-else-if="showRaw" class="px-5 py-4 max-h-96 overflow-y-auto">
            <pre class="text-xs font-mono text-gray-500 whitespace-pre-wrap break-all leading-relaxed">{{ whoisData.raw_text }}</pre>
          </div>
          <div v-else class="divide-y divide-gray-800/30">
            <div class="px-5 py-4 grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-4">
              <template v-for="f in whoisFields" :key="f.key">
                <div v-if="whoisData[f.key]" class="flex flex-col gap-0.5">
                  <span class="text-[11px] text-gray-600 uppercase tracking-wider">{{ f.label }}</span>
                  <span class="text-sm text-gray-200 font-mono">{{ whoisData[f.key] }}</span>
                </div>
              </template>
              <div v-if="dnssecStatus" class="flex flex-col gap-1">
                <span class="text-[11px] text-gray-600 uppercase tracking-wider">DNSSEC</span>
                <span :class="['text-xs font-mono px-2 py-0.5 rounded w-fit',
                  dnssecStatus.ok ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                  : 'bg-gray-800 text-gray-500 border border-gray-700']">
                  {{ dnssecStatus.label }}
                </span>
              </div>
            </div>
            <div v-if="whoisData.name_servers?.length" class="px-5 py-4">
              <span class="text-[11px] text-gray-600 uppercase tracking-wider block mb-2">Name Servers</span>
              <div class="flex flex-wrap gap-2">
                <span v-for="ns in whoisData.name_servers" :key="ns"
                  class="text-xs font-mono bg-violet-500/10 text-violet-400 border border-violet-500/20 px-2 py-1 rounded-lg">{{ ns }}</span>
              </div>
            </div>
            <div v-if="whoisData.status?.length" class="px-5 py-4">
              <span class="text-[11px] text-gray-600 uppercase tracking-wider block mb-2">Status</span>
              <div class="flex flex-wrap gap-2">
                <span v-for="s in whoisData.status" :key="s"
                  class="text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-1 rounded-lg">{{ s }}</span>
              </div>
            </div>
            <div v-if="whoisData.emails?.length" class="px-5 py-4">
              <span class="text-[11px] text-gray-600 uppercase tracking-wider block mb-2">Emails</span>
              <div class="space-y-1">
                <div v-for="e in whoisData.emails" :key="e" class="text-sm text-gray-400 font-mono">{{ e }}</div>
              </div>
            </div>
          </div>
        </section>

        <!-- Copy full result -->
        <div class="flex justify-end pt-1">
          <button @click="copy(JSON.stringify(result, null, 2), 'full')"
            class="px-3 py-1.5 border border-gray-800 hover:border-gray-700 hover:bg-gray-900 rounded-lg text-xs text-gray-600 hover:text-gray-300 transition-colors inline-flex items-center gap-1.5">
            <svg v-if="copiedKey !== 'full'" class="size-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184"/>
            </svg>
            <svg v-else class="size-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/>
            </svg>
            {{ copiedKey === 'full' ? 'Copied!' : 'Copy full result as JSON' }}
          </button>
        </div>
      </div>

      <!-- ╔══════════════════════════════════════════════════════════════════╗ -->
      <!-- ║  BULK RESULTS                                                    ║ -->
      <!-- ╚══════════════════════════════════════════════════════════════════╝ -->
      <div v-if="mode === 'bulk' && bulkResults.length">
        <div class="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
          <div class="px-5 py-3.5 border-b border-gray-800/60 flex items-center gap-3">
            <svg class="size-4 text-gray-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75">
              <path stroke-linecap="round" stroke-linejoin="round" d="M8.25 6.75h12M8.25 12h12m-12 5.25h12M3.75 6.75h.007v.008H3.75V6.75zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zM3.75 12h.007v.008H3.75V12zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm-.375 5.25h.007v.008H3.75v-.008zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z"/>
            </svg>
            <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400 flex-1">
              Results <span class="text-gray-600 font-normal normal-case ml-1">{{ bulkResults.length }} domains</span>
            </h2>
            <button @click="copy(JSON.stringify(bulkResults, null, 2), 'bulk')" title="Copy as JSON"
              class="p-1.5 rounded-md text-gray-600 hover:text-gray-300 hover:bg-gray-800 transition-colors">
              <svg v-if="copiedKey !== 'bulk'" class="size-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184"/>
              </svg>
              <svg v-else class="size-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/>
              </svg>
            </button>
            <button @click="bulkResults = []"
              class="p-1.5 rounded-md text-gray-600 hover:text-red-400 hover:bg-red-500/10 transition-colors" title="Clear results">
              <svg class="size-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
              </svg>
            </button>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full">
              <thead>
                <tr class="border-b border-gray-800/60">
                  <th class="px-5 py-3 text-left text-[11px] font-medium text-gray-600 uppercase tracking-wider">Domain</th>
                  <th class="px-4 py-3 text-center text-[11px] font-medium text-gray-600 uppercase tracking-wider">DNS</th>
                  <th class="px-4 py-3 text-center text-[11px] font-medium text-gray-600 uppercase tracking-wider">SPF</th>
                  <th class="px-5 py-3 text-left text-[11px] font-medium text-gray-600 uppercase tracking-wider">Registrar</th>
                  <th class="px-5 py-3 text-left text-[11px] font-medium text-gray-600 uppercase tracking-wider">Expires</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-800/30">
                <tr v-for="item in bulkResults" :key="item.domain ?? item.dns?.domain"
                  class="hover:bg-gray-800/20 transition-colors">
                  <td class="px-5 py-3.5 font-mono text-sm text-gray-200">{{ item.domain ?? item.dns?.domain }}</td>
                  <td class="px-4 py-3.5 text-center">
                    <span v-if="item.error" class="text-[11px] text-red-400/70 bg-red-500/10 px-2 py-0.5 rounded-full">error</span>
                    <svg v-else-if="bulkDnsOk(item)" class="size-4 text-emerald-400 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/>
                    </svg>
                    <svg v-else class="size-4 text-red-400 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                  </td>
                  <td class="px-4 py-3.5 text-center">
                    <svg v-if="bulkSpf(item)" class="size-4 text-emerald-400 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/>
                    </svg>
                    <span v-else class="text-gray-700">—</span>
                  </td>
                  <td class="px-5 py-3.5 text-xs text-gray-400 max-w-[180px] truncate">{{ (item.whois ?? item)?.registrar || '—' }}</td>
                  <td class="px-5 py-3.5 text-xs font-mono" :class="bulkExpClass(item)">
                    {{ bulkWhoisExp(item) ? bulkWhoisExp(item).slice(0, 10) : '—' }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ╔══════════════════════════════════════════════════════════════════╗ -->
      <!-- ║  COMPARE RESULTS                                                 ║ -->
      <!-- ╚══════════════════════════════════════════════════════════════════╝ -->
      <div v-if="mode === 'compare' && (cmpR1 || cmpR2)" class="space-y-4">
        <!-- DNS comparison -->
        <div class="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
          <div class="px-5 py-3.5 border-b border-gray-800/60 flex items-center gap-3">
            <svg class="size-4 text-gray-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75">
              <path stroke-linecap="round" stroke-linejoin="round" d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5"/>
            </svg>
            <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400">DNS Comparison</h2>
          </div>
          <div class="grid grid-cols-2 divide-x divide-gray-800/60">
            <div v-for="(res, idx) in [cmpR1, cmpR2]" :key="idx" class="px-4 py-4">
              <p class="text-xs font-mono text-violet-400 mb-3 flex items-center gap-1.5">
                <span class="text-gray-700 text-[10px]">{{ idx + 1 }}</span>
                {{ idx === 0 ? cmpD1 : cmpD2 }}
              </p>
              <div v-if="res && (res.dns ?? res)?.error" class="text-xs text-red-400/80 mb-2">{{ (res.dns ?? res).error }}</div>
              <div v-for="rtype in ['A','AAAA','MX','NS','TXT']" :key="rtype" class="mb-3 last:mb-0">
                <div v-if="cmpRecords(res, rtype).length">
                  <span :class="['text-xs font-bold px-1.5 py-0.5 rounded border inline-block mb-1', recordColors[rtype] || 'bg-gray-800 text-gray-400']">{{ rtype }}</span>
                  <div v-for="(rec, i) in cmpRecords(res, rtype)" :key="i"
                    class="text-xs font-mono text-gray-300 break-all pl-2 leading-relaxed border-l border-gray-800/60 ml-1">
                    {{ rec.value }}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- WHOIS comparison -->
        <div class="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
          <div class="px-5 py-3.5 border-b border-gray-800/60 flex items-center gap-3">
            <svg class="size-4 text-gray-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75">
              <path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z"/>
            </svg>
            <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400">WHOIS Comparison</h2>
          </div>
          <div class="grid grid-cols-2 divide-x divide-gray-800/60">
            <div v-for="(res, idx) in [cmpR1, cmpR2]" :key="idx" class="px-4 py-4 space-y-3.5">
              <p class="text-xs font-mono text-violet-400 flex items-center gap-1.5">
                <span class="text-gray-700 text-[10px]">{{ idx + 1 }}</span>
                {{ idx === 0 ? cmpD1 : cmpD2 }}
              </p>
              <div v-for="f in [...whoisFields, {key:'dnssec', label:'DNSSEC'}]" :key="f.key" class="flex flex-col gap-0.5">
                <span class="text-[11px] text-gray-600 uppercase tracking-wider">{{ f.label }}</span>
                <span class="text-xs text-gray-300 font-mono break-all">{{ cmpWhoisField(res, f.key) }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- ── Empty state ─────────────────────────────────────────────────── -->
      <div v-if="!loading && !bulkLoading && !cmpLoading && !error && !result && !bulkResults.length && !cmpR1 && !cmpR2"
        class="py-24 text-center">
        <div class="inline-flex size-14 rounded-2xl bg-gray-900 border border-gray-800 items-center justify-center mb-4">
          <svg class="size-7 text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"/>
          </svg>
        </div>
        <p class="text-sm font-medium text-gray-500 mb-1">
          <span v-if="mode === 'bulk'">Paste up to 20 domains and scan at once</span>
          <span v-else-if="mode === 'compare'">Compare DNS &amp; WHOIS for two domains side by side</span>
          <span v-else>Enter a domain to inspect its DNS and WHOIS records</span>
        </p>
        <p class="text-xs text-gray-700">
          <span v-if="mode === 'full'">Full Scan includes DNS records, SSL certificate, and email security</span>
          <span v-else-if="mode === 'dns'">Queries A, AAAA, CNAME, MX, NS, TXT, PTR, SRV, and CAA records</span>
          <span v-else-if="mode === 'whois'">Returns registrar, dates, name servers, and DNSSEC status</span>
          <span v-else-if="mode === 'bulk'">Results include DNS health, SPF presence, registrar, and expiry date</span>
          <span v-else>Highlights differences in A, MX, NS records and WHOIS registration data</span>
        </p>
      </div>

    </main>
  </div>
</template>
