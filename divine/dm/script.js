(function() {
  // State
  let ws = null;
  let currentUserId = null;
  let currentThread = null;
  let threads = [];
  let requests = [];

  // Elements
  const threadList = document.getElementById('threadList');
  const requestSection = document.getElementById('requestSection');
  const requestBadge = document.getElementById('requestBadge');
  const requestList = document.getElementById('requestList');
  const chatView = document.getElementById('chatView');
  const activeChat = document.getElementById('activeChat');
  const chatHeaderName = document.getElementById('chatHeaderName');
  const chatUserAvatar = document.getElementById('chatUserAvatar');
  const messagesList = document.getElementById('messagesList');
  const messageInput = document.getElementById('messageInput');
  const sendBtn = document.getElementById('sendBtn');
  const newDmBtn = document.getElementById('newDmBtn');
  const newDmModal = document.getElementById('newDmModal');
  const closeModalBtn = document.getElementById('closeModalBtn');
  const userSearch = document.getElementById('userSearch');
  const searchResults = document.getElementById('searchResults');
  const inviteSection = document.getElementById('inviteSection');
  const inviteMessage = document.getElementById('inviteMessage');
  const sendInviteBtn = document.getElementById('sendInviteBtn');

  let selectedInviteUser = null;
  let searchTimeout = null;

  // Initialize
  async function init() {
    await loadUserInfo();
    await loadRequests();
    await loadThreads();
    connectWebSocket();
    setupEventListeners();
  }

  async function loadUserInfo() {
    try {
      const res = await fetch('/api/me');
      const data = await res.json();
      if (data.ok && data.user) {
        currentUserId = data.user.id;
      }
    } catch (e) {
      console.error('Failed to load user info:', e);
    }
  }

  async function loadRequests() {
    try {
      const res = await fetch('/api/dm/pending-requests');
      const data = await res.json();
      if (data.ok) {
        requests = data.requests || [];
        renderRequests();
      }
    } catch (e) {
      console.error('Failed to load requests:', e);
    }
  }

  async function loadThreads() {
    try {
      const res = await fetch('/api/dm/threads');
      const data = await res.json();
      if (data.ok) {
        threads = data.threads || [];
        renderThreads();
      }
    } catch (e) {
      console.error('Failed to load threads:', e);
    }
  }

  function renderRequests() {
    if (requests.length === 0) {
      requestSection.style.display = 'none';
      return;
    }

    requestSection.style.display = 'block';
    requestBadge.textContent = requests.length;
    
    requestList.innerHTML = requests.map(r => `
      <div class="requestItem" data-request-id="${r.id}">
        <div class="requestFrom">${escapeHtml(r.from.username)}</div>
        ${r.inviteMessage ? `<div class="requestMessage">${escapeHtml(r.inviteMessage)}</div>` : ''}
        <div class="requestActions">
          <button class="btnRequest btnAccept" data-action="accept" data-request-id="${r.id}">Accept</button>
          <button class="btnRequest btnDecline" data-action="decline" data-request-id="${r.id}">Decline</button>
        </div>
      </div>
    `).join('');
  }

  function renderThreads() {
    if (threads.length === 0) {
      threadList.innerHTML = '<div class="emptyState">No messages yet</div>';
      return;
    }

    threadList.innerHTML = threads.map(t => {
      const initial = t.otherUser.username.charAt(0).toUpperCase();
      const isActive = currentThread && currentThread.id === t.id;
      return `
        <div class="threadItem ${isActive ? 'active' : ''}" data-thread-id="${t.id}">
          <div class="threadUser">
            <div class="userAvatar">${initial}</div>
            <div class="threadInfo">
              <div class="threadName">${escapeHtml(t.otherUser.username)}</div>
              <div class="threadPreview">Click to open</div>
            </div>
            ${t.unreadCount > 0 ? `<div class="unreadBadge">${t.unreadCount > 9 ? '9+' : t.unreadCount}</div>` : ''}
          </div>
        </div>
      `;
    }).join('');
  }

  async function openThread(threadId) {
    const thread = threads.find(t => t.id === threadId);
    if (!thread) return;

    currentThread = thread;
    renderThreads(); // Re-render to show active state

    // Show chat view
    chatView.querySelector('.emptyChat').style.display = 'none';
    activeChat.style.display = 'flex';

    // Set header
    const initial = thread.otherUser.username.charAt(0).toUpperCase();
    chatUserAvatar.textContent = initial;
    chatHeaderName.textContent = thread.otherUser.username;

    // Load messages
    await loadMessages(threadId);

    // Mark as read
    await markThreadRead(threadId);
  }

  async function loadMessages(threadId) {
    try {
      const res = await fetch(`/api/dm/threads/${threadId}/messages`);
      const data = await res.json();
      if (data.ok) {
        renderMessages(data.messages || []);
      }
    } catch (e) {
      console.error('Failed to load messages:', e);
    }
  }

  function renderMessages(messages) {
    if (messages.length === 0) {
      messagesList.innerHTML = '<div class="emptyState">No messages yet. Say hi!</div>';
      return;
    }

    messagesList.innerHTML = messages.map(m => {
      const isOwn = m.from.id === currentUserId;
      const initial = m.from.username.charAt(0).toUpperCase();
      const time = formatTime(m.createdAt);
      return `
        <div class="message ${isOwn ? 'own' : ''}">
          <div class="userAvatar">${initial}</div>
          <div class="messageBubble">
            ${!isOwn ? `<div class="messageAuthor">${escapeHtml(m.from.username)}</div>` : ''}
            <div class="messageText">${escapeHtml(m.message)}</div>
            <div class="messageTime">${time}</div>
          </div>
        </div>
      `;
    }).join('');

    // Scroll to bottom
    setTimeout(() => {
      const container = document.getElementById('messagesContainer');
      container.scrollTop = container.scrollHeight;
    }, 100);
  }

  async function sendMessage() {
    if (!currentThread) return;

    const text = messageInput.value.trim();
    if (!text) return;

    try {
      sendBtn.disabled = true;
      const res = await fetch(`/api/dm/threads/${currentThread.id}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text })
      });

      const data = await res.json();
      if (data.ok) {
        messageInput.value = '';
        await loadMessages(currentThread.id);
      } else {
        alert(data.error || 'Failed to send message');
      }
    } catch (e) {
      console.error('Send message error:', e);
      alert('Network error');
    } finally {
      sendBtn.disabled = false;
    }
  }

  async function markThreadRead(threadId) {
    try {
      await fetch(`/api/dm/threads/${threadId}/read`, { method: 'POST' });
      // Update local unread count
      const thread = threads.find(t => t.id === threadId);
      if (thread) {
        thread.unreadCount = 0;
        renderThreads();
      }
    } catch (e) {
      console.error('Mark read error:', e);
    }
  }

  async function handleRequestAction(requestId, action) {
    try {
      const res = await fetch(`/api/dm/request/${requestId}/${action}`, { method: 'POST' });
      const data = await res.json();
      
      if (data.ok) {
        // Remove from requests
        requests = requests.filter(r => r.id !== requestId);
        renderRequests();
        
        if (action === 'accept') {
          // Reload threads to show new one
          await loadThreads();
          // Open the new thread
          if (data.threadId) {
            openThread(data.threadId);
          }
        }
      } else {
        alert(data.error || 'Action failed');
      }
    } catch (e) {
      console.error('Request action error:', e);
      alert('Network error');
    }
  }

  function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
      console.log('WebSocket connected');
    };
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleWsMessage(data);
      } catch (e) {
        console.error('WS message error:', e);
      }
    };
    
    ws.onclose = () => {
      console.log('WebSocket closed, reconnecting...');
      setTimeout(connectWebSocket, 3000);
    };
    
    ws.onerror = (err) => {
      console.error('WebSocket error:', err);
    };
  }

  function handleWsMessage(data) {
    console.log('WS message:', data);
    
    switch (data.type) {
      case 'new_request':
        loadRequests();
        break;
      case 'request_accepted':
        loadThreads();
        break;
      case 'new_message':
        if (currentThread && data.threadId === currentThread.id) {
          loadMessages(currentThread.id);
          markThreadRead(currentThread.id);
        } else {
          loadThreads();
        }
        break;
      case 'unread_update':
        loadThreads();
        break;
    }
  }

  // New DM modal
  function openNewDmModal() {
    newDmModal.style.display = 'flex';
    userSearch.value = '';
    searchResults.innerHTML = '';
    inviteSection.style.display = 'none';
    selectedInviteUser = null;
  }

  function closeNewDmModal() {
    newDmModal.style.display = 'none';
  }

  async function searchUsers(query) {
    if (!query || query.length < 2) {
      searchResults.innerHTML = '';
      return;
    }

    try {
      const res = await fetch(`/api/dm/search-users?q=${encodeURIComponent(query)}`);
      const data = await res.json();
      
      if (data.ok) {
        const users = data.users || [];
        if (users.length === 0) {
          searchResults.innerHTML = '<div class="searchEmpty">No users found</div>';
        } else {
          searchResults.innerHTML = users.map(u => `
            <div class="searchResultItem" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}">
              ${escapeHtml(u.username)}
            </div>
          `).join('');
        }
      }
    } catch (e) {
      console.error('Search error:', e);
    }
  }

  async function sendInvite() {
    if (!selectedInviteUser) return;

    const message = inviteMessage.value.trim();

    try {
      sendInviteBtn.disabled = true;
      const res = await fetch('/api/dm/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          toUserId: selectedInviteUser.id,
          inviteMessage: message
        })
      });

      const data = await res.json();
      if (data.ok) {
        alert('Invite sent!');
        closeNewDmModal();
      } else {
        alert(data.error || 'Failed to send invite');
      }
    } catch (e) {
      console.error('Send invite error:', e);
      alert('Network error');
    } finally {
      sendInviteBtn.disabled = false;
    }
  }

  // Event listeners
  function setupEventListeners() {
    // Thread selection
    threadList.addEventListener('click', (e) => {
      const item = e.target.closest('.threadItem');
      if (item) {
        const threadId = item.dataset.threadId;
        openThread(threadId);
      }
    });

    // Request actions
    requestList.addEventListener('click', (e) => {
      const btn = e.target.closest('.btnRequest');
      if (btn) {
        const action = btn.dataset.action;
        const requestId = parseInt(btn.dataset.requestId, 10);
        handleRequestAction(requestId, action);
      }
    });

    // Send message
    sendBtn.addEventListener('click', sendMessage);
    messageInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });

    // Auto-resize textarea
    messageInput.addEventListener('input', () => {
      messageInput.style.height = 'auto';
      messageInput.style.height = messageInput.scrollHeight + 'px';
    });

    // New DM modal
    newDmBtn.addEventListener('click', openNewDmModal);
    closeModalBtn.addEventListener('click', closeNewDmModal);
    newDmModal.addEventListener('click', (e) => {
      if (e.target === newDmModal) closeNewDmModal();
    });

    // User search
    userSearch.addEventListener('input', (e) => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        searchUsers(e.target.value.trim());
      }, 300);
    });

    // Select user from search
    searchResults.addEventListener('click', (e) => {
      const item = e.target.closest('.searchResultItem');
      if (item) {
        selectedInviteUser = {
          id: item.dataset.userId,
          username: item.dataset.username
        };
        inviteSection.style.display = 'block';
        userSearch.value = item.dataset.username;
        searchResults.innerHTML = '';
      }
    });

    // Send invite
    sendInviteBtn.addEventListener('click', sendInvite);
  }

  // Utilities
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
    if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
    if (diff < 604800000) return Math.floor(diff / 86400000) + 'd ago';
    
    return date.toLocaleDateString();
  }

  // Start
  init();
})();
