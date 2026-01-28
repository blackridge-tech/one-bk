(function() {
  const banReasonEl = document.getElementById('banReason');
  const banDurationEl = document.getElementById('banDuration');
  const showAppealBtn = document.getElementById('showAppealBtn');
  const appealForm = document.getElementById('appealForm');
  const appealTextEl = document.getElementById('appealText');
  const cancelAppealBtn = document.getElementById('cancelAppealBtn');
  const submitAppealBtn = document.getElementById('submitAppealBtn');
  const appealMessageEl = document.getElementById('appealMessage');

  // Fetch ban details
  async function loadBanInfo() {
    try {
      const res = await fetch('/api/me');
      if (!res.ok) {
        banReasonEl.textContent = 'Unknown';
        banDurationEl.textContent = 'Unknown';
        return;
      }
      
      const data = await res.json();
      if (!data.ok) {
        banReasonEl.textContent = 'Unknown';
        banDurationEl.textContent = 'Unknown';
        return;
      }
      
      // Try to get DM ban info from a dedicated endpoint
      const banRes = await fetch('/api/dm/ban-info');
      if (banRes.ok) {
        const banData = await banRes.json();
        if (banData.ok && banData.ban) {
          banReasonEl.textContent = banData.ban.reason || 'No reason provided';
          
          const until = banData.ban.bannedUntil;
          const now = Date.now();
          if (until > now + (365 * 24 * 60 * 60 * 1000)) {
            banDurationEl.textContent = 'Permanent';
          } else {
            const diff = until - now;
            const days = Math.floor(diff / (24 * 60 * 60 * 1000));
            const hours = Math.floor((diff % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));
            
            if (days > 0) {
              banDurationEl.textContent = `${days} day${days !== 1 ? 's' : ''}`;
            } else if (hours > 0) {
              banDurationEl.textContent = `${hours} hour${hours !== 1 ? 's' : ''}`;
            } else {
              banDurationEl.textContent = 'Less than 1 hour';
            }
          }
        } else {
          banReasonEl.textContent = 'Unknown';
          banDurationEl.textContent = 'Unknown';
        }
      } else {
        banReasonEl.textContent = 'Violation of DM guidelines';
        banDurationEl.textContent = 'See owner for details';
      }
    } catch (e) {
      console.error('Failed to load ban info:', e);
      banReasonEl.textContent = 'Error loading ban info';
      banDurationEl.textContent = 'Error';
    }
  }

  function showMessage(text, isError) {
    appealMessageEl.textContent = text;
    appealMessageEl.className = 'message ' + (isError ? 'error' : 'success');
    appealMessageEl.style.display = 'block';
  }

  function hideMessage() {
    appealMessageEl.style.display = 'none';
  }

  showAppealBtn.addEventListener('click', () => {
    appealForm.classList.add('show');
    showAppealBtn.style.display = 'none';
    hideMessage();
  });

  cancelAppealBtn.addEventListener('click', () => {
    appealForm.classList.remove('show');
    showAppealBtn.style.display = 'block';
    appealTextEl.value = '';
    hideMessage();
  });

  submitAppealBtn.addEventListener('click', async () => {
    const text = appealTextEl.value.trim();
    if (!text) {
      showMessage('Please enter your appeal text.', true);
      return;
    }

    try {
      submitAppealBtn.disabled = true;
      hideMessage();

      const res = await fetch('/api/dm/appeal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ appealText: text })
      });

      const data = await res.json();

      if (!res.ok || !data.ok) {
        showMessage(data.error || 'Failed to submit appeal', true);
        return;
      }

      showMessage('Appeal submitted successfully! Owners will review it.', false);
      appealTextEl.value = '';
      
      setTimeout(() => {
        appealForm.classList.remove('show');
        showAppealBtn.style.display = 'block';
        showAppealBtn.disabled = true;
        showAppealBtn.textContent = 'Appeal Submitted';
      }, 2000);

    } catch (e) {
      console.error('Appeal submission error:', e);
      showMessage('Network error. Please try again.', true);
    } finally {
      submitAppealBtn.disabled = false;
    }
  });

  // Load ban info on page load
  loadBanInfo();
})();
