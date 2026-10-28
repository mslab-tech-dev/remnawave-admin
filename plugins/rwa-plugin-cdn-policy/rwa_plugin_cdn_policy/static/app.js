(() => {
  const pluginId = 'cdn_policy'
  const api = `/api/v2/plugins/${pluginId}`
  const style = `
    .cdn-policy { color: var(--text-primary, #202a32); font: 14px/1.45 system-ui, sans-serif; }
    .cdn-policy h1 { margin: 0 0 18px; font-size: 22px; }
    .cdn-policy table { width: 100%; border-collapse: collapse; }
    .cdn-policy th, .cdn-policy td { padding: 10px 12px; border-bottom: 1px solid var(--border, #d6dde2); text-align: left; }
    .cdn-policy th { color: var(--text-secondary, #53616b); font-size: 12px; font-weight: 600; }
    .cdn-policy select, .cdn-policy input { min-height: 34px; padding: 5px 8px; border: 1px solid var(--border, #c8d1d8); border-radius: 4px; background: var(--surface, #fff); color: inherit; }
    .cdn-policy input[type=number] { width: 112px; }
    .cdn-policy .toolbar { display: flex; gap: 8px; margin: 16px 0; }
    .cdn-policy button { min-height: 36px; padding: 6px 12px; border: 1px solid var(--border, #bcc8d0); border-radius: 4px; background: var(--surface, #fff); color: inherit; cursor: pointer; }
    .cdn-policy button.primary { background: #126b61; border-color: #126b61; color: #fff; }
    .cdn-policy .status { min-height: 22px; color: var(--text-secondary, #53616b); }
    .cdn-policy .check { width: 18px; height: 18px; }
    @media (max-width: 700px) { .cdn-policy table, .cdn-policy tbody, .cdn-policy tr, .cdn-policy td { display: block; } .cdn-policy thead { display: none; } .cdn-policy tr { padding: 8px 0; border-bottom: 1px solid var(--border, #d6dde2); } .cdn-policy td { border: 0; padding: 4px 8px; } }
  `

  const request = async (path, options = {}) => {
    const response = await fetch(`${api}${path}`, {
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
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
          element.style.color = error ? '#b42318' : ''
        }
      }

      const render = () => {
        page.replaceChildren(styleNode)
        const title = document.createElement('h1')
        title.textContent = 'Политика CDN-inbound'
        page.append(title)
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
        page.append(table)
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
        page.append(toolbar, message)

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