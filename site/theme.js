(() => {
  const media = matchMedia('(prefers-color-scheme: dark)');
  let preference = 'system';
  try { preference = localStorage.getItem('agentuplink-theme') || 'system'; } catch {}
  if (!['system', 'light', 'dark'].includes(preference)) preference = 'system';
  function apply() {
    const theme = preference === 'system' ? (media.matches ? 'dark' : 'light') : preference;
    document.documentElement.dataset.theme = theme;
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = theme === 'dark' ? '#181d1a' : '#f5f6f5';
  }
  apply();
  media.addEventListener('change', apply);
  document.addEventListener('DOMContentLoaded', () => {
    const label = document.createElement('label');
    label.className = 'theme-control';
    label.textContent = 'Theme';
    const select = document.createElement('select');
    select.setAttribute('aria-label', 'Colour theme');
    for (const value of ['system', 'light', 'dark']) {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = value[0].toUpperCase() + value.slice(1);
      select.append(option);
    }
    select.value = preference;
    select.addEventListener('change', () => {
      preference = select.value;
      try { localStorage.setItem('agentuplink-theme', preference); } catch {}
      apply();
    });
    label.append(select);
    document.querySelector('header').append(label);
  });
})();
