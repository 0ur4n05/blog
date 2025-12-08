const ui = {
	mobileMenuBtn: document.getElementById('mobile-menu-btn'),
	fileTree: document.getElementById('fileTree'),
	overlay: document.getElementById('overlay'),
	cursor: document.getElementById('cursor'),
	filePathText: document.getElementById('file-path-txt'),

	init() {
		this.mobileMenuBtn.addEventListener('click', () => this.toggleSidebar());
		this.overlay.addEventListener('click', () => this.closeSidebar());
		window.addEventListener('resize', () => this.updateCursorPosition());
		setInterval(() => this.updateCursorPosition(), 50);
		this.updateCursorPosition();
	},

	toggleSidebar() {
		this.fileTree.classList.toggle('open');
		this.overlay.classList.toggle('open');
	},

	closeSidebar() {
		this.fileTree.classList.remove('open');
		this.overlay.classList.remove('open');
	},

	updateCursorPosition() {
		const rect = this.filePathText.getBoundingClientRect();
		// Since cursor is now inside a flex container next to text, 
		// we might not need absolute positioning if CSS handles it nicely.
		// But if we keep absolute, we need to correct it.
		// With the new flex layout: #file-path { display: flex; alignItems: center; }
		// The cursor is static relative to the text now. 
		// Let's remove the manual positioning logic if the CSS flex works as expected.
		// However, if the cursor is style="position: absolute", we need to remove that or update it.
		// In the CSS provided, #cursor doesn't have position: absolute anymore.
		// So this function can be empty/removed, but let's keep it safe.
		this.cursor.style.position = 'static';
	}
};

async function fetchAndCopyContent(url) {
	try {
		const response = await fetch(`${window.location.protocol}//${window.location.host}/${url}`);
		if (!response.ok) throw new Error('Network response was not ok');
		const content = await response.text();
		await navigator.clipboard.writeText(content);

		// Show feedback
		const btn = document.getElementById('copy-button');
		const originalIcon = btn.innerHTML;
		btn.innerHTML = '<i class="fa-solid fa-check"></i>';
		setTimeout(() => {
			btn.innerHTML = originalIcon;
		}, 2000);

	} catch (error) {
		console.error('Failed to copy', error);
		alert('Failed to copy content');
	}
}

const fileExplorer = {
	currentPath: '/',
	fileContent: document.getElementById('fileContent'),

	async fetchDirectory(path) {
		try {
			const response = await fetch(`/ls?path=${encodeURIComponent(path)}`);
			return await response.json();
		} catch (error) {
			console.error('Error fetching directory:', error);
			return { type: 'error', message: error.message };
		}
	},

	async fetchFile(path) {
		try {
			const response = await fetch(`/ls?path=${encodeURIComponent(path)}`);
			return await response.json();
		} catch (error) {
			console.error('Error fetching file:', error);
			return { type: 'error', message: error.message };
		}
	},

	async renderFile(path) {
		const data = await this.fetchFile(path);
		if (data.type === 'file') {
			this.fileContent.innerHTML = data.contents;
			// On mobile, close sidebar when file is opened
			if (window.innerWidth <= 768) {
				ui.closeSidebar();
			}
		} else {
			this.fileContent.textContent = `Error: ${data.message || 'Unable to render file'}`;
		}
	},

	resolvePath(path) {
		if (path.startsWith('/')) return path;
		return `${this.currentPath}/${path}`.replace(/\/+/g, '/');
	}
};


function setDownloadLink(dir, filename) {
	const downloadButton = document.getElementById('download-button');
	// Remove old listeners to prevent multiple clicks (simple way: clone/replace)
	const newBtn = downloadButton.cloneNode(true);
	downloadButton.parentNode.replaceChild(newBtn, downloadButton);

	newBtn.addEventListener('click', function () {
		const downloadLink = document.createElement('a');
		downloadLink.href = `${window.location.protocol}//${window.location.host}/${dir}`;
		downloadLink.download = filename;
		downloadLink.click();
	});
}

function setupCopyButton(url) {
	const copyBtn = document.getElementById('copy-button');
	// Remove old listeners
	const newBtn = copyBtn.cloneNode(true);
	copyBtn.parentNode.replaceChild(newBtn, copyBtn);

	newBtn.addEventListener('click', () => {
		fetchAndCopyContent(url);
	});
}

async function renderFileTree(container, path = '/') {
	container.innerHTML = '';
	const data = await fileExplorer.fetchDirectory(path);
	const cdirpath = fileExplorer.resolvePath(`${window.location.pathname}`);
	let cdir = { type: 'error' };
	try {
		cdir = await fileExplorer.fetchDirectory(cdirpath);
	} catch (e) { }


	if (data.type === 'directory') {
		for (const item of data.contents) {
			const button = document.createElement('button');
			const isDir = item.type === 'dir';
			button.className = isDir ? 'folder-icon' : 'file-icon';
			button.textContent = item.filename;

			const itemPath = fileExplorer.resolvePath(`${path}${item.filename}`);

			// Auto open readme if in root
			if (item.filename == "README.md" && cdir.type === "directory" && path === '/') {
				await fileExplorer.renderFile(itemPath);
			}

			if (!isDir) {
				button.onclick = async () => {
					setupCopyButton(`content${path}${item.filename}`);
					await fileExplorer.renderFile(itemPath);
					setDownloadLink(`content${path}${item.filename}`, item.filename);

					document.getElementById('file-path-txt').textContent = `${path}${item.filename}`;
					history.pushState({}, "", `${path}${item.filename}`);
				}
			} else {
				button.onclick = async () => {
					const childrenDiv = button.nextElementSibling;
					if (childrenDiv && childrenDiv.classList.contains('children')) {
						if (childrenDiv.style.display === 'none') {
							childrenDiv.style.display = 'block';
						} else {
							childrenDiv.style.display = 'none';
						}
					} else {
						const newChildrenDiv = document.createElement('div');
						newChildrenDiv.className = 'children';
						await renderFileTree(newChildrenDiv, itemPath);
						button.parentNode.insertBefore(newChildrenDiv, button.nextSibling);
					}
					document.getElementById('file-path-txt').textContent = itemPath;
					history.pushState({}, "", itemPath);
				}
			}
			container.appendChild(button);
		}
	} else {
		const errorMsg = document.createElement('div');
		errorMsg.textContent = `Error: ${data.message || 'Unable to load directory'}`;
		container.appendChild(errorMsg);
	}
}

async function main() {
	ui.init();

	if (window.location.pathname != "/") {
		const itemPath = fileExplorer.resolvePath(`${window.location.pathname}`);
		document.getElementById('file-path-txt').textContent = `${window.location.pathname}`;

		let data;
		try {
			data = await fileExplorer.fetchDirectory(itemPath);
		} catch (e) { data = { type: 'error' }; }

		if (data.type === 'directory') {
			renderFileTree(document.getElementById('fileTree'), window.location.pathname);
		} else {
			// It's a file, but we need to verify if it exists by checking parent dir? 
			// The ls endpoint returns file content if it is a file?
			// "ls" returns contents array for dir, or {type:'file', contents:'...'} for file.
			// Let's assume renderFile handles finding it.

			await fileExplorer.renderFile(itemPath);
			// Render root tree so user can navigate elsewhere
			renderFileTree(document.getElementById('fileTree'));

			// Setup buttons for this file
			setDownloadLink(`content${itemPath}`, itemPath.split('/').pop());
			setupCopyButton(`content${itemPath}`);
		}
	} else {
		renderFileTree(document.getElementById('fileTree'));
	}
}

main();

