(() => {
  const pluginId = 'cdn_policy'
  const api = `/api/v2/plugins/${pluginId}`
  // Цвета берём из тех же CSS-переменных, что и панель (shadcn-конвенция:
  // HSL-триплет внутри hsl(var(--x))). Свои hex-значения ломали тёмную тему:
  // переменных вроде --text-primary в панели нет, и подставлялся тёмный
  // текст на тёмном фоне. Fallback-триплеты — только для тёмной темы.
  const style = `
    .cdn-policy { color: hsl(var(--foreground, 220 9% 84%)); font: 14px/1.45 system-ui, sans-serif; }
    .cdn-policy .panel {
      border: 1px solid var(--glass-border, hsl(var(--border, 220 14% 18%)));
      background: var(--glass-bg, hsl(var(--card, 220 20% 10%)));
      border-radius: 0.75rem;
      padding: 20px;
      backdrop-filter: blur(var(--glass-blur, 12px));
    }
    .cdn-policy h1 { margin: 0 0 4px; font-size: 18px; font-weight: 600; letter-spacing: -0.01em; }
    .cdn-policy .hint { margin: 0 0 16px; font-size: 13px; color: hsl(var(--muted-foreground, 220 9% 56%)); }
    .cdn-policy table { width: 100%; border-collapse: collapse; }
    .cdn-policy thead tr { background: var(--glass-bg-hover, transparent); }
    .cdn-policy th { padding: 10px 12px; text-align: left; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: hsl(var(--muted-foreground, 220 9% 56%)); }
    .cdn-policy td { padding: 10px 12px; text-align: left; border-top: 1px solid hsl(var(--border, 220 14% 18%)); }
    .cdn-policy tbody tr:hover { background: var(--glass-bg-hover, hsl(var(--accent, 220 14% 16%))); }
    .cdn-policy select, .cdn-policy input { min-height: 34px; padding: 5px 8px; border: 1px solid hsl(var(--input, 220 14% 18%)); border-radius: calc(var(--radius, 0.5rem) - 0.2rem); background: hsl(var(--background, 220 22% 8%)); color: hsl(var(--foreground, 220 9% 84%)); }
    .cdn-policy input[type=number] { width: 112px; }
    .cdn-policy input:disabled { opacity: 0.5; cursor: not-allowed; }
    .cdn-policy select:focus-visible, .cdn-policy input:focus-visible { outline: 2px solid hsl(var(--ring, 239 84% 67%)); outline-offset: 1px; }
    .cdn-policy .check { width: 18px; height: 18px; accent-color: hsl(var(--primary, 239 84% 67%)); }
    .cdn-policy .toolbar { display: flex; gap: 8px; margin: 18px 0 0; }
    .cdn-policy button { min-height: 36px; padding: 6px 14px; border: 1px solid hsl(var(--input, 220 14% 18%)); border-radius: calc(var(--radius, 0.5rem) - 0.2rem); background: hsl(var(--secondary, 220 14% 16%)); color: hsl(var(--secondary-foreground, 220 9% 84%)); cursor: pointer; font-weight: 500; }
    .cdn-policy button:hover { background: hsl(var(--accent, 220 14% 16%)); color: hsl(var(--accent-foreground, 220 9% 84%)); }
    .cdn-policy button.primary { background: hsl(var(--primary, 239 84% 67%)); border-color: hsl(var(--primary, 239 84% 67%)); color: hsl(var(--primary-foreground, 0 0% 100%)); }
    .cdn-policy button.primary:hover { filter: brightness(1.08); }
    .cdn-policy .status { min-height: 20px; margin-top: 12px; font-size: 13px; color: hsl(var(--muted-foreground, 220 9% 56%)); }
    @media (max-width: 700px) {
      .cdn-policy .panel { padding: 14px; }
      .cdn-policy table, .cdn-policy tbody, .cdn-policy tr, .cdn-policy td { display: block; }
      .cdn-policy thead { display: none; }
      .cdn-policy tr { padding: 8px 0; border-top: 1px solid hsl(var(--border, 220 14% 18%)); }
      .cdn-policy td { border: 0; padding: 4px 0; }
      .cdn-policy .toolbar { flex-direction: column; }
    }
  `

  // Панель защищает мутации double-submit cookie: значение читаемой cookie
  // rw_csrf нужно вернуть в заголовке X-CSRF-Token, иначе PUT/POST отвечают
  // «CSRF token missing or invalid».
  const csrfToken = () => {
    const match = document.cookie.match(/(?:^|;\s*)rw_csrf=([^;]+)/)
    return match ? decodeURIComponent(match[1]) : ''
  }

  const request = async (path, options = {}) => {
    const method = (options.method || 'GET').toUpperCase()
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) }
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      const token = csrfToken()
      if (token) headers['X-CSRF-Token'] = token
    }
    const response = await fetch(`${api}${path}`, {
      credentials: 'same-origin',
      ...options,
      headers,
    })
    if (!response.ok) throw new Error((await response.text()) || `HTTP ${response.status}`)
    return response.json()
  }

  window.rwaPluginUI = window.rwaPluginUI || {}
  window.rwaPluginUI[pluginId] = {
    mount(root) {
      const styleNode = document.createElement('style')
      styleNode.textContent = style
      root.append(styleNode)
      const page = document.createElement('section')
      page.className = 'cdn-policy'
      root.append(page)
      let rows = []
      let nodes = []

      const status = (text, error = false) => {
        const element = page.querySelector('.status')
        if (element) {
          element.textContent = text
          element.style.color = error ? 'hsl(var(--destructive, 0 72% 51%))' : ''
        }
      }

      const render = () => {
        page.replaceChildren(styleNode)
        // Карточка в стиле панели: тот же glass-фон и рамка, что у блоков настроек.
        const panel = document.createElement('div')
        panel.className = 'panel'
        const title = document.createElement('h1')
        title.textContent = 'Политика CDN-inbound'
        const hint = document.createElement('p')
        hint.className = 'hint'
        hint.textContent = 'Шейпинг и дроп действуют только на клиентов CDN-инбаундов, подключённых не из мобильной сети. Мобильные и неклассифицированные адреса не ограничиваются.'
        panel.append(title, hint)
        const table = document.createElement('table')
        table.innerHTML = '<thead><tr><th>Включить</th><th>Нода / inbound</th><th>Действие</th><th>Скорость, кбит/с</th></tr></thead><tbody></tbody>'
        const body = table.querySelector('tbody')
        for (const node of nodes) {
          for (const inbound of node.inbounds || []) {
            const existing = rows.find((item) => item.node_uuid === node.uuid && item.inbounds.some((rule) => rule.tag === inbound.tag && rule.port === inbound.port))
            const selected = existing?.inbounds.find((rule) => rule.tag === inbound.tag && rule.port === inbound.port)
            const tr = document.createElement('tr')
            const checkCell = document.createElement('td')
            const checkbox = document.createElement('input')
            checkbox.type = 'checkbox'
            checkbox.className = 'check'
            checkbox.checked = Boolean(selected)
            checkCell.append(checkbox)
            const labelCell = document.createElement('td')
            labelCell.textContent = `${node.name} / ${inbound.tag} :${inbound.port}`
            const actionCell = document.createElement('td')
            const action = document.createElement('select')
            action.innerHTML = '<option value="shape">Шейпить</option><option value="drop">Дропать</option>'
            action.value = selected?.action || 'shape'
            actionCell.append(action)
            const rateCell = document.createElement('td')
            const rate = document.createElement('input')
            rate.type = 'number'
            rate.min = '1'
            rate.max = '100000000'
            rate.step = '1'
            rate.value = String(selected?.rate_kbit || 1024)
            rateCell.append(rate)
            const toggleRate = () => { rate.disabled = action.value === 'drop' }
            action.addEventListener('change', toggleRate)
            toggleRate()
            tr.append(checkCell, labelCell, actionCell, rateCell)
            tr.dataset.node = node.uuid
            tr.dataset.tag = inbound.tag
            tr.dataset.port = String(inbound.port)
            body.append(tr)
          }
        }
        panel.append(table)
        const toolbar = document.createElement('div')
        toolbar.className = 'toolbar'
        const save = document.createElement('button')
        save.className = 'primary'
        save.textContent = 'Сохранить'
        const sync = document.createElement('button')
        sync.textContent = 'Синхронизировать сейчас'
        toolbar.append(save, sync)
        const message = document.createElement('div')
        message.className = 'status'
        panel.append(toolbar, message)
        page.append(panel)

        save.addEventListener('click', async () => {
          try {
            const selected = [...page.querySelectorAll('tbody tr')].filter((tr) => tr.querySelector('.check').checked)
            const grouped = new Map()
            for (const tr of selected) {
              const nodeId = tr.dataset.node
              if (!grouped.has(nodeId)) grouped.set(nodeId, { node_uuid: nodeId, inbounds: [] })
              const actionValue = tr.querySelector('select').value
              const item = { tag: tr.dataset.tag, port: Number(tr.dataset.port), action: actionValue }
              if (actionValue === 'shape') item.rate_kbit = Number(tr.querySelector('input[type=number]').value)
              grouped.get(nodeId).inbounds.push(item)
            }
            const result = await request('/settings', { method: 'PUT', body: JSON.stringify({ nodes: [...grouped.values()] }) })
            rows = [...grouped.values()]
            render()
            status(`Сохранено. Отправлено нодам: ${result.sync.pushed}; нод недоступно: ${result.sync.offline}.`)
          } catch (error) { status(error.message, true) }
        })
        sync.addEventListener('click', async () => {
          try {
            const result = await request('/sync', { method: 'POST' })
            status(`Отправлено нодам: ${result.pushed}; нод недоступно: ${result.offline}.`)
          } catch (error) { status(error.message, true) }
        })
      }

      Promise.all([request('/nodes'), request('/settings')]).then(([nodeData, settings]) => {
        nodes = nodeData
        rows = settings.nodes || []
        render()
      }).catch((error) => {
        page.textContent = `Не удалось загрузить настройки: ${error.message}`
      })
    },
    unmount() {},
  }
})()