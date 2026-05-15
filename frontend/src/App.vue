<script setup>
import { ref, computed } from 'vue'

/** Empty field → API uses this resolver (Google Public DNS). */
const DEFAULT_DNS_HINT = '8.8.8.8'
const RESOLVER_PLACEHOLDER = 'Defaults to 8.8.8.8'

const domain = ref('')
const resolver = ref('')
const resolverError = ref('')
const mode = ref('full')
const loading = ref(false)
const error = ref('')
const result = ref(null)

function validateResolver(value) {
  const t = value.trim()
  if (!t) {
    resolverError.value = ''
    return true
  }
  let s = t
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1)
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    const parts = s.split('.').map(Number)
    if (parts.every((n) => n >= 0 && n <= 255)) {
      resolverError.value = ''
      return true
    }
  }
  if (s.includes(':') && /^[0-9a-f:.]+$/i.test(s)) {
    resolverError.value = ''
    return true
  }
  resolverError.value = 'Enter a valid IPv4 or IPv6 address (e.g. 1.1.1.1 or 2606:4700:4700::1111).'
  return false
}

function formatApiError(body, status) {
  if (!body?.detail) return `Request failed (${status})`
  const d = body.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d)) return d.map((e) => e.msg || JSON.stringify(e)).join(' ')
  return String(d)
}

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
  const dns = result.value.dns ?? result.value
  const whois = result.value.whois ?? result.value
  if (dns?.error && whois?.error) return dns.error
  return null
})

const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'PTR', 'SRV']

const recordColors = {
  A: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  AAAA: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  CNAME: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  MX: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  NS: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  TXT: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
  PTR: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  SRV: 'bg-pink-500/10 text-pink-400 border-pink-500/20',
}

async function lookup() {
  const d = domain.value.trim()
  if (!d) return

  if (mode.value !== 'whois' && !validateResolver(resolver.value)) {
    error.value = ''
    result.value = null
    return
  }

  loading.value = true
  error.value = ''
  result.value = null

  const r = resolver.value.trim()
  const resolverParam = r ? `&resolver=${encodeURIComponent(r)}` : ''
  const endpoints = {
    full: `/api/inspect?domain=${encodeURIComponent(d)}${resolverParam}`,
    dns: `/api/dns?domain=${encodeURIComponent(d)}${resolverParam}`,
    whois: `/api/whois?domain=${encodeURIComponent(d)}`,
  }

  try {
    const res = await fetch(endpoints[mode.value])
    if (!res.ok) {
      const body = await res.json().catch(() => null)
      throw new Error(formatApiError(body, res.status))
    }
    result.value = await res.json()
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

function onKey(e) {
  if (e.key === 'Enter') lookup()
}

const whoisFields = [
  { key: 'registrar', label: 'Registrar' },
  { key: 'whois_server', label: 'WHOIS Server' },
  { key: 'creation_date', label: 'Created' },
  { key: 'expiration_date', label: 'Expires' },
  { key: 'updated_date', label: 'Updated' },
  { key: 'dnssec', label: 'DNSSEC' },
]
</script>

<template>
  <div class="min-h-screen bg-gray-950 text-gray-100">
    <!-- Header -->
    <header class="border-b border-gray-800/60">
      <div class="max-w-5xl mx-auto px-4 py-6 sm:px-6">
        <div class="flex items-center gap-3">
          <div class="size-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
            <svg class="size-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
            </svg>
          </div>
          <div>
            <h1 class="text-lg font-semibold tracking-tight">DomainXray</h1>
            <p class="text-xs text-gray-500">DNS &amp; WHOIS Analysis Tool</p>
          </div>
        </div>
      </div>
    </header>

    <main class="max-w-5xl mx-auto px-4 sm:px-6 py-8">
      <!-- Search -->
      <div class="space-y-4">
        <div class="flex gap-2">
          <div class="relative flex-1">
            <input
              v-model="domain"
              @keydown="onKey"
              type="text"
              placeholder="Enter domain name (e.g. google.com)"
              class="w-full bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-cyan-600 focus:ring-1 focus:ring-cyan-600 transition-colors"
            />
          </div>
          <button
            @click="lookup"
            :disabled="loading || !domain.trim() || (mode !== 'whois' && !!resolverError)"
            class="px-6 py-3 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg text-sm font-medium transition-colors shrink-0"
          >
            <span v-if="loading" class="flex items-center gap-2">
              <svg class="animate-spin size-4" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Scanning...
            </span>
            <span v-else>Scan</span>
          </button>
        </div>

        <!-- Mode (left) · Custom resolver (right-aligned) -->
        <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
          <div class="flex gap-1 bg-gray-900 rounded-lg p-1 w-fit shrink-0">
            <button
              v-for="m in [
                { id: 'full', label: 'Full Scan' },
                { id: 'dns', label: 'DNS' },
                { id: 'whois', label: 'WHOIS' },
              ]"
              :key="m.id"
              @click="mode = m.id; error = ''"
              :class="[
                'px-3.5 sm:px-4 py-2 rounded-md text-xs font-medium transition-colors',
                mode === m.id
                  ? 'bg-gray-800 text-gray-100 shadow-sm'
                  : 'text-gray-500 hover:text-gray-300',
              ]"
            >
              {{ m.label }}
            </button>
          </div>

          <div
            v-show="mode !== 'whois'"
            class="flex flex-col gap-1.5 w-full sm:w-auto sm:ml-auto sm:items-end sm:text-right min-w-0"
          >
            <div class="flex flex-col items-end gap-1.5 sm:flex-row sm:flex-nowrap sm:items-center sm:justify-end sm:gap-2.5 w-full sm:w-auto">
              <label
                for="resolver-input"
                class="text-xs font-medium text-gray-400 tracking-tight shrink-0"
              >Custom resolver</label>
              <div class="relative w-full max-w-[13.5rem] sm:w-[13.5rem] shrink-0">
                <input
                  id="resolver-input"
                  v-model="resolver"
                  type="text"
                  autocomplete="off"
                  spellcheck="false"
                  :placeholder="RESOLVER_PLACEHOLDER"
                  :title="`Leave blank for ${DEFAULT_DNS_HINT} (Google Public DNS).`"
                  :class="[
                    'w-full h-9 rounded-lg border bg-gray-900/80 px-3 pr-8 text-xs font-mono text-gray-200 text-left placeholder:text-gray-500 outline-none transition-[border-color,box-shadow]',
                    resolverError
                      ? 'border-red-500/50 focus:border-red-500/70 focus:ring-1 focus:ring-red-500/30'
                      : 'border-gray-800 focus:border-cyan-600/50 focus:ring-1 focus:ring-cyan-600/30',
                  ]"
                  @input="(e) => { validateResolver(e.target.value); if (!resolverError) error = '' }"
                  @keydown="onKey"
                />
                <button
                  v-if="resolver.trim()"
                  type="button"
                  @click="resolver = ''; resolverError = ''"
                  class="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-1 text-gray-500 hover:bg-gray-800 hover:text-gray-300 transition-colors"
                  aria-label="Clear override"
                >
                  <svg class="size-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
            <p
              v-if="resolverError"
              class="text-[11px] text-red-400/90 leading-snug w-full max-w-[13.5rem] text-right"
            >
              {{ resolverError }}
            </p>
          </div>
        </div>
      </div>

      <!-- Error -->
      <div v-if="error" class="mt-6 bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-3 text-sm text-red-400">
        {{ error }}
      </div>

      <!-- Domain-level error -->
      <div v-if="result && domainError" class="mt-8">
        <div class="bg-red-500/10 border border-red-500/20 rounded-xl px-5 py-6 text-center">
          <svg class="size-8 text-red-400 mx-auto mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
          </svg>
          <p class="text-sm font-medium text-red-400">{{ domainError }}</p>
          <p v-if="whoisData?.error && whoisData.error !== domainError" class="text-xs text-red-400/60 mt-1">{{ whoisData.error }}</p>
        </div>
      </div>

      <!-- Results -->
      <div v-if="result && !domainError" class="mt-8 space-y-6">

        <!-- DNS Section -->
        <section v-if="mode !== 'whois' && dnsData" class="bg-gray-900/50 border border-gray-800/60 rounded-xl overflow-hidden">
          <div class="px-5 py-4 border-b border-gray-800/60 flex items-center justify-between">
            <h2 class="text-sm font-semibold tracking-wide uppercase text-gray-400">DNS Records</h2>
            <span class="text-xs text-gray-600 font-mono">resolver: {{ dnsData.resolver }}</span>
          </div>

          <!-- DNS top-level error -->
          <div v-if="dnsData.error" class="px-5 py-6 text-center text-sm text-red-400">
            {{ dnsData.error }}
          </div>

          <div v-else-if="Object.keys(dnsData.records).length === 0" class="px-5 py-8 text-center text-sm text-gray-600">
            No DNS records found.
          </div>

          <div v-else class="divide-y divide-gray-800/40">
            <div v-for="rtype in recordTypes" :key="rtype">
              <div v-if="dnsData.records[rtype]" class="px-5 py-4">
                <div class="flex items-center gap-2 mb-3">
                  <span :class="['text-xs font-bold px-2 py-0.5 rounded border', recordColors[rtype] || 'bg-gray-800 text-gray-400']">
                    {{ rtype }}
                  </span>
                  <span class="text-xs text-gray-600">{{ dnsData.records[rtype].length }} record{{ dnsData.records[rtype].length > 1 ? 's' : '' }}</span>
                </div>
                <div class="space-y-1.5">
                  <div
                    v-for="(rec, i) in dnsData.records[rtype]"
                    :key="i"
                    class="flex items-baseline gap-3 text-sm font-mono"
                  >
                    <span class="text-gray-200 break-all">{{ rec.value }}</span>
                    <span v-if="rec.priority != null" class="text-xs text-amber-500/80">pri:{{ rec.priority }}</span>
                    <span class="text-xs text-gray-700 ml-auto shrink-0">TTL {{ rec.ttl }}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- DNS Errors -->
          <div v-if="Object.keys(dnsData.errors || {}).length" class="px-5 py-3 border-t border-gray-800/60">
            <div v-for="(err, rtype) in dnsData.errors" :key="rtype" class="text-xs text-red-400">
              <span class="font-bold">{{ rtype }}:</span> {{ err }}
            </div>
          </div>
        </section>

        <!-- WHOIS Section -->
        <section v-if="mode !== 'dns' && whoisData" class="bg-gray-900/50 border border-gray-800/60 rounded-xl overflow-hidden">
          <div class="px-5 py-4 border-b border-gray-800/60">
            <h2 class="text-sm font-semibold tracking-wide uppercase text-gray-400">WHOIS Information</h2>
          </div>

          <div v-if="whoisData.error" class="px-5 py-4 text-sm text-red-400">
            {{ whoisData.error }}
          </div>

          <div v-else class="divide-y divide-gray-800/30">
            <!-- Key-Value Fields -->
            <div class="px-5 py-4 grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-3">
              <template v-for="f in whoisFields" :key="f.key">
                <div v-if="whoisData[f.key]" class="flex flex-col">
                  <span class="text-xs text-gray-600 uppercase tracking-wider">{{ f.label }}</span>
                  <span class="text-sm text-gray-200 font-mono mt-0.5">{{ whoisData[f.key] }}</span>
                </div>
              </template>
            </div>

            <!-- Name Servers -->
            <div v-if="whoisData.name_servers?.length" class="px-5 py-4">
              <span class="text-xs text-gray-600 uppercase tracking-wider">Name Servers</span>
              <div class="mt-2 flex flex-wrap gap-2">
                <span
                  v-for="ns in whoisData.name_servers"
                  :key="ns"
                  class="text-xs font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-2 py-1 rounded"
                >
                  {{ ns }}
                </span>
              </div>
            </div>

            <!-- Status -->
            <div v-if="whoisData.status?.length" class="px-5 py-4">
              <span class="text-xs text-gray-600 uppercase tracking-wider">Status</span>
              <div class="mt-2 flex flex-wrap gap-2">
                <span
                  v-for="s in whoisData.status"
                  :key="s"
                  class="text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-1 rounded"
                >
                  {{ s }}
                </span>
              </div>
            </div>

            <!-- Emails -->
            <div v-if="whoisData.emails?.length" class="px-5 py-4">
              <span class="text-xs text-gray-600 uppercase tracking-wider">Emails</span>
              <div class="mt-1.5 space-y-1">
                <div v-for="e in whoisData.emails" :key="e" class="text-sm text-gray-300 font-mono">{{ e }}</div>
              </div>
            </div>
          </div>
        </section>
      </div>

      <!-- Empty State -->
      <div v-if="!result && !loading && !error" class="mt-24 text-center">
        <div class="inline-flex size-16 rounded-2xl bg-gray-900 border border-gray-800 items-center justify-center mb-4">
          <svg class="size-8 text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5a17.92 17.92 0 01-8.716-2.247m0 0A9 9 0 013 12c0-1.328.288-2.584.804-3.718" />
          </svg>
        </div>
        <p class="text-sm text-gray-600">Enter a domain to start scanning</p>
      </div>
    </main>
  </div>
</template>
