(() => {
  const container = document.querySelector('[data-release-info]');
  if (!container) return;
  const repo = 'andymac4182/agentuplink';
  const targets = ['x86_64-unknown-linux-gnu', 'aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-pc-windows-msvc'];
  const labels = ['Linux x64 (Ubuntu 24.04 baseline)', 'macOS Apple Silicon', 'macOS Intel', 'Windows x64'];
  const releaseUrl = `https://github.com/${repo}/releases`;
  function link(text, href) {
    const element = document.createElement('a');
    element.textContent = text;
    element.href = href;
    return element;
  }
  function message(text) {
    const p = document.createElement('p');
    p.textContent = text;
    container.replaceChildren(p, link('View GitHub releases', releaseUrl));
  }
  function assetFor(release, target) {
    const name = `agentuplink-${release.tag_name}-${target}.${target.endsWith('windows-msvc') ? 'zip' : 'tar.gz'}`;
    const find = suffix => release.assets.find(a => a.name === name + suffix && a.state === 'uploaded' && a.size > 0 && a.browser_download_url.startsWith(`https://github.com/${repo}/releases/download/`));
    return [find(''), find('.sha256')];
  }
  fetch(`https://api.github.com/repos/${repo}/releases?per_page=100`, { signal: AbortSignal.timeout(10000), headers: { Accept: 'application/vnd.github+json' } })
    .then(response => { if (!response.ok) throw new Error('Release lookup unavailable'); return response.json(); })
    .then(releases => {
      const candidates = releases.filter(r => !r.draft && /^v\d+\.\d+\.\d+-main\.\d+\.[0-9a-f]{12}$/.test(r.tag_name) && Array.isArray(r.assets) && targets.every(t => assetFor(r, t).every(Boolean)));
      candidates.sort((a, b) => Number(b.tag_name.split('-main.')[1].split('.')[0]) - Number(a.tag_name.split('-main.')[1].split('.')[0]));
      const release = candidates[0];
      if (!release) { message('No complete development release is published yet. The first download becomes available after main CI and all platform builds pass.'); return; }
      const heading = document.createElement('p');
      heading.textContent = `Latest development version: ${release.tag_name}`;
      const list = document.createElement('ul');
      targets.forEach((target, i) => {
        const [archive, checksum] = assetFor(release, target);
        const item = document.createElement('li');
        item.append(link(labels[i], archive.browser_download_url), ' · ', link('SHA-256', checksum.browser_download_url));
        list.append(item);
      });
      container.replaceChildren(heading, list, link('Release notes', `${releaseUrl}/tag/${encodeURIComponent(release.tag_name)}`));
    }).catch(() => message('The release service could not be reached. Check GitHub releases for available versions; no cached version is assumed current.'));
})();
