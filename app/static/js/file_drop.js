(() => {
  const inputs = document.querySelectorAll('input[type="file"]');

  function formatAccept(raw) {
    if (!raw) return "";
    const parts = raw.split(",").map((part) => part.trim()).filter(Boolean);
    const mapped = parts.map((part) => {
      if (part === "text/plain") return ".txt";
      if (part === "application/pdf") return ".pdf";
      if (part === "application/vnd.openxmlformats-officedocument.presentationml.presentation") return ".pptx";
      return part;
    });
    return Array.from(new Set(mapped)).join(", ");
  }

  function setupInput(input) {
    if (input.dataset.fileDropReady === "1") return;
    input.dataset.fileDropReady = "1";

    const wrapper = input.parentElement;
    if (!wrapper) return;
    wrapper.classList.add("file-drop");
    input.classList.add("file-drop__input");

    const zone = document.createElement("div");
    zone.className = "file-drop__zone";
    zone.tabIndex = 0;
    zone.setAttribute("role", "button");
    zone.setAttribute("aria-label", "Arrastra y suelta archivos o haz clic para seleccionar.");

    const acceptText = formatAccept(input.getAttribute("accept"));
    const multiText = input.multiple ? " Puedes soltar varios archivos." : " Solo un archivo.";
    zone.innerHTML = `
      <span class="file-drop__title">Arrastra y suelta archivos o haz clic para seleccionar.</span>
      <span class="file-drop__meta">Formatos: ${acceptText || "cualquiera"}.${multiText}</span>
    `;

    const list = document.createElement("ul");
    list.className = "file-drop__list";
    list.hidden = true;

    const label = wrapper.querySelector(`label[for="${input.id}"]`);
    if (label) {
      label.insertAdjacentElement("afterend", zone);
    } else {
      wrapper.insertBefore(zone, input);
    }
    input.insertAdjacentElement("afterend", list);

    const dt = new DataTransfer();

    function sync() {
      input.files = dt.files;
      renderList();
    }

    function renderList() {
      const files = Array.from(dt.files);
      list.innerHTML = "";
      if (!files.length) {
        list.hidden = true;
        return;
      }
      list.hidden = false;
      files.forEach((file, index) => {
        const item = document.createElement("li");
        item.className = "file-drop__item";

        const name = document.createElement("span");
        name.className = "file-drop__name";
        name.textContent = file.name;

        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "file-drop__remove";
        remove.textContent = "Quitar";
        remove.addEventListener("click", () => {
          dt.items.remove(index);
          sync();
        });

        item.appendChild(name);
        item.appendChild(remove);
        list.appendChild(item);
      });
    }

    function addFiles(fileList) {
      let files = Array.from(fileList || []);
      if (!files.length) return;
      if (!input.multiple) {
        files = files.slice(0, 1);
        dt.items.clear();
      }
      files.forEach((file) => {
        dt.items.add(file);
      });
      sync();
    }

    zone.addEventListener("click", () => input.click());
    zone.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        input.click();
      }
    });

    zone.addEventListener("dragover", (event) => {
      event.preventDefault();
      zone.classList.add("is-dragover");
    });
    zone.addEventListener("dragleave", () => {
      zone.classList.remove("is-dragover");
    });
    zone.addEventListener("drop", (event) => {
      event.preventDefault();
      zone.classList.remove("is-dragover");
      addFiles(event.dataTransfer ? event.dataTransfer.files : []);
    });

    input.addEventListener("change", () => addFiles(input.files));
  }

  inputs.forEach((input) => setupInput(input));
})();
