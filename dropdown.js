// DOM-rendered single-select menu, including keyboard navigation and typeahead.
export function createDropdown(id, onChange) {
  const button = document.getElementById(id);
  const list = document.getElementById(`${id}-options`);
  let options = [], value = 'all', active = 0, search = '', lastTyped = 0;
  const isOpen = () => !list.hidden;
  function close() { list.hidden = true; button.setAttribute('aria-expanded', 'false'); button.removeAttribute('aria-activedescendant'); }
  function highlight(index) {
    active = (index + options.length) % options.length;
    [...list.children].forEach((node, i) => node.classList.toggle('active', i === active));
    const node = list.children[active];
    if (node) { button.setAttribute('aria-activedescendant', node.id); node.scrollIntoView({block: 'nearest'}); }
  }
  function open() {
    if (button.disabled) return;
    list.hidden = false; button.setAttribute('aria-expanded', 'true');
    highlight(Math.max(0, options.findIndex(option => option.value === value)));
  }
  function select(next, notify = false) {
    const option = options.find(option => option.value === next);
    if (!option) return;
    value = next; button.textContent = option.label; button.title = option.label;
    [...list.children].forEach((node, i) => node.setAttribute('aria-selected', String(options[i].value === value)));
    close();
    if (notify) onChange();
  }
  button.addEventListener('click', () => isOpen() ? close() : open());
  button.addEventListener('keydown', event => {
    const {key} = event;
    if (key === 'Tab') { close(); return; }
    if (key === 'Escape') { event.preventDefault(); close(); return; }
    if (['ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter', ' '].includes(key)) {
      event.preventDefault();
      if (!isOpen()) { open(); if (key !== 'Home' && key !== 'End') return; }
      if (key === 'Enter' || key === ' ') select(options[active].value, true);
      else highlight(key === 'Home' ? 0 : key === 'End' ? options.length - 1 : active + (key === 'ArrowDown' ? 1 : -1));
    } else if (key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      const now = Date.now(); search = now - lastTyped > 700 ? key : search + key; lastTyped = now;
      if (!isOpen()) open();
      const index = options.findIndex(option => option.label.toLowerCase().startsWith(search.toLowerCase()));
      if (index >= 0) highlight(index);
    }
  });
  document.addEventListener('pointerdown', event => { if (!button.parentElement.contains(event.target)) close(); });
  button.addEventListener('blur', close);
  return {
    get value() { return value; },
    set value(next) { select(next); },
    setOptions(next, disabled = false) {
      close(); options = next; button.disabled = disabled;
      list.replaceChildren(...options.map((option, index) => {
        const node = document.createElement('div');
        node.id = `${id}-option-${index}`; node.role = 'option'; node.textContent = option.label;
        node.addEventListener('pointerdown', event => event.preventDefault());
        node.addEventListener('click', () => { select(option.value, true); button.focus(); });
        return node;
      }));
      select(options[0].value);
    },
  };
}
