(function () {
  var ta = document.getElementById('content');
  var cc = document.getElementById('count');
  if (!ta || !cc) return;
  ta.addEventListener('input', function () { cc.textContent = ta.value.length; });
})();
