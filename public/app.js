document.querySelector('#load').onclick = async () => { const response = await fetch('/api/keyring'); document.querySelector('#keys').textContent = JSON.stringify(await response.json(), null, 2); };
