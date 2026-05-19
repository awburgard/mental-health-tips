(function () {
  document.querySelectorAll('form.confirm-delete').forEach(function (f) {
    f.addEventListener('submit', function (e) {
      if (!window.confirm('Delete this message from Slack and wipe the record? This cannot be undone.')) {
        e.preventDefault();
      }
    });
  });
})();
