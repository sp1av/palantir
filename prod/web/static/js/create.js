document.addEventListener("DOMContentLoaded", function () {
    const offensiveMode = document.getElementById("offensive-mode");
    const defensiveMode = document.getElementById("defensive-mode");
    const offensiveForm = document.getElementById("offensive-form");
    const defensiveForm = document.getElementById("defensive-form");
    const scheduleSelect = document.getElementById("schedule");
    const scheduleOptions = document.getElementById("schedule-options");
    const addContainerButton = document.getElementById("add-container");
    const containerIdsDiv = document.getElementById("container-ids");

    offensiveMode.addEventListener("click", function () {
        offensiveForm.classList.remove("hidden");
        defensiveForm.classList.add("hidden");
    });

    defensiveMode.addEventListener("click", function () {
        defensiveForm.classList.remove("hidden");
        offensiveForm.classList.add("hidden");
    });

    scheduleSelect.addEventListener("change", function () {
        if (scheduleSelect.value === "scheduled") {
            scheduleOptions.classList.remove("hidden");
        } else {
            scheduleOptions.classList.add("hidden");
        }
    });

    addContainerButton.addEventListener("click", function () {
        const containerDiv = document.createElement("div");
        containerDiv.style.display = "flex";
        containerDiv.style.alignItems = "center";

        const newInput = document.createElement("input");
        newInput.type = "text";
        newInput.name = "container_id[]";
        newInput.required = true;

        const removeButton = document.createElement("button");
        removeButton.textContent = "-";
        removeButton.classList.add("remove-container");
        removeButton.addEventListener("click", function () {
            containerIdsDiv.removeChild(containerDiv);
        });

        containerDiv.appendChild(newInput);
        containerDiv.appendChild(removeButton);
        containerIdsDiv.appendChild(containerDiv);
    });
});

