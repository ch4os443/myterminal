
// Element selectors
const ipInput = document.querySelector("#ip");
const portInput = document.querySelector("#port");
const listenerSelect = document.querySelector("#listener-selection");
const shellSelect = document.querySelector("#shell");
// const autoCopySwitch = document.querySelector("#auto-copy-switch");
const operatingSystemSelect = document.querySelector("#os-options");
const encodingSelect = document.querySelector('#encoding');
const searchBox = document.querySelector('#searchBox');
const listenerCommand = document.querySelector("#listener-command");
const reverseShellCommand = document.querySelector("#reverse-shell-command");
const bindShellCommand = document.querySelector("#bind-shell-command");
const msfVenomCommand = document.querySelector("#msfvenom-command");
const hoaxShellCommand = document.querySelector("#hoaxshell-command");

const FilterOperatingSystemType = {
    'All': 'all',
    'Windows': 'windows',
    'Linux': 'linux',
    'Mac': 'mac'
};

const hoaxshell_listener_types = {
	"Windows CMD cURL" : "cmd-curl",
	"PowerShell IEX" : "ps-iex",
	"PowerShell IEX Constr Lang Mode" : "ps-iex-cm",
	"PowerShell Outfile" : "ps-outfile",
	"PowerShell Outfile Constr Lang Mode" : "ps-outfile-cm",
	"Windows CMD cURL https" : "cmd-curl -c /your/cert.pem -k /your/key.pem",
	"PowerShell IEX https" : "ps-iex -c /your/cert.pem -k /your/key.pem",
	"PowerShell IEX Constr Lang Mode https" : "ps-iex-cm -c /your/cert.pem -k /your/key.pem",
	"PowerShell Outfile https" : "ps-outfile -c /your/cert.pem -k /your/key.pem",
	"PowerShell Outfile Constr Lang Mode https" : "ps-outfile-cm -c /your/cert.pem -k /your/key.pem"
};

// These querySelectors will be null if the reverse shell tab is not active.
// We will re-assign them when the tab becomes active.
let rsgIpInput, rsgPortInput, rsgListenerSelect, rsgShellSelect, rsgOperatingSystemSelect, rsgEncodingSelect, rsgSearchBox;
let rsgListenerCommand, rsgReverseShellCommand, rsgBindShellCommand, rsgMsfVenomCommand, rsgHoaxShellCommand;
let rsgReverseTab, rsgBindTab, rsgMsfvenomTab, rsgHoaxShellTab;

function initializeRSGSelectors() {
    rsgIpInput = document.querySelector("#ip");
    rsgPortInput = document.querySelector("#port");
    rsgListenerSelect = document.querySelector("#listener-selection");
    rsgShellSelect = document.querySelector("#shell");
    rsgOperatingSystemSelect = document.querySelector("#os-options");
    rsgEncodingSelect = document.querySelector('#encoding');
    rsgSearchBox = document.querySelector('#searchBox');
    rsgListenerCommand = document.querySelector("#listener-command");
    rsgReverseShellCommand = document.querySelector("#reverse-shell-command");
    rsgBindShellCommand = document.querySelector("#bind-shell-command");
    rsgMsfVenomCommand = document.querySelector("#msfvenom-command");
    rsgHoaxShellCommand = document.querySelector("#hoaxshell-command");

    rsgReverseTab = document.querySelector("#reverse-tab");
    rsgBindTab = document.querySelector("#bind-tab");
    rsgMsfvenomTab = document.querySelector("#msfvenom-tab");
    rsgHoaxShellTab = document.querySelector("#hoaxshell-tab");

    if (rsgOperatingSystemSelect) {
        rsgOperatingSystemSelect.addEventListener("change", (event) => {
            const selectedOS = event.target.value;
            rsg.setState({
                filterOperatingSystem: selectedOS,
            });
        });
    }

    if (rsgReverseTab) {
        rsgReverseTab.addEventListener("click", () => {
            rsg.setState({
                commandType: CommandType.ReverseShell,
            });
        });
    }
    if (rsgBindTab) {
        rsgBindTab.addEventListener("click", () => {
            rsg.setState({
                commandType: CommandType.BindShell,
                encoding: "None"
            });
        });
        // Duplicate event listener in original, kept for consistency if intended.
        rsgBindTab.addEventListener("click", () => {
            let bindShellSelection = document.querySelector("#bind-shell-selection");
            if(bindShellSelection) bindShellSelection.innerHTML = "";
            rsg.setState({
                commandType: CommandType.BindShell
            });
        });
    }
    if (rsgMsfvenomTab) {
        rsgMsfvenomTab.addEventListener("click", () => {
            let msfVenomSelection = document.querySelector("#msfvenom-selection");
            if(msfVenomSelection) msfVenomSelection.innerHTML = "";
            rsg.setState({
                commandType: CommandType.MSFVenom,
                encoding: "None"
            });
        });
    }
    if (rsgHoaxShellTab) {
        rsgHoaxShellTab.addEventListener("click", () => {
            let hoaxShellSelection = document.querySelector("#hoaxshell-selection");
            if(hoaxShellSelection) hoaxShellSelection.innerHTML = "";
            rsg.setState({
                commandType: CommandType.HoaxShell,
                encoding: "None"
            });
        });
    }

    var rawLinkButtons = document.querySelectorAll('.raw-listener');
    for (const button of rawLinkButtons) {
        button.addEventListener("click", () => {
            const rawLink = RawLink.generate(rsg);
            window.location = rawLink;
        });
    }
}

const filterCommandData = function (data, { commandType, filterOperatingSystem = FilterOperatingSystemType.All, filterText = '' }) {
    return data.filter(item => {
        if (!item.meta.includes(commandType)) {
            return false;
        }
        var hasOperatingSystemMatch = (filterOperatingSystem === FilterOperatingSystemType.All) || item.meta.includes(filterOperatingSystem);
        var hasTextMatch = item.name.toLowerCase().indexOf(filterText.toLowerCase()) >= 0;
        return hasOperatingSystemMatch && hasTextMatch;
    });
}

const query = new URLSearchParams(location.hash.substring(1));

const fixedEncodeURIComponent = function (str) {
    return encodeURIComponent(str).replace(/[!'()*]/g, function(c) {
        return '%' + c.charCodeAt(0).toString(16).toUpperCase();
    });
}

const parsePortOrDefault = function (value, defaultPort = 9001) {
    if (value === null || value === undefined) return defaultPort;
    const number = Number(value);
    const isValidPort = (Number.isSafeInteger(number) && number >= 0 && number <= 65535);
    return isValidPort ? number : defaultPort;
};

const rsg = {
    ip: (query.get('ip') || localStorage.getItem('ip') || '10.10.10.10').replace(/[^a-zA-Z0-9.\-]/g, ''),
    port: parsePortOrDefault(query.get('port') || localStorage.getItem('port')),
    payload: query.get('payload') || localStorage.getItem('payload') || 'windows/x64/meterpreter/reverse_tcp',
    // Original script had 'payload' twice, assuming second was 'type'
    type: query.get('type') || localStorage.getItem('type') || 'cmd-curl',
    shell: query.get('shell') || localStorage.getItem('shell') || (typeof rsgData !== 'undefined' ? rsgData.shells[0] : '/bin/bash'),
    listener: query.get('listener') || localStorage.getItem('listener') || (typeof rsgData !== 'undefined' ? rsgData.listenerCommands[0][1] : 'nc -lvnp {port}'),
    encoding: query.get('encoding') || localStorage.getItem('encoding') || 'None',
    selectedValues: {},
    commandType: CommandType.ReverseShell,
    filterOperatingSystem: query.get('filterOperatingSystem') || localStorage.getItem('filterOperatingSystem') || FilterOperatingSystemType.All,
    filterText: query.get('filterText') || localStorage.getItem('filterText') || '',

    uiElements: {
        [CommandType.ReverseShell]: {
            listSelection: '#reverse-shell-selection',
            command: '#reverse-shell-command'
        },
        [CommandType.BindShell]: {
            listSelection: '#bind-shell-selection',
            command: '#bind-shell-command',
        },
        [CommandType.MSFVenom]: {
            listSelection: '#msfvenom-selection',
            command: '#msfvenom-command'
        },
        [CommandType.HoaxShell]: {
            listSelection: '#hoaxshell-selection',
            command: '#hoaxshell-command'
        }
    },

    copyToClipboard: (text) => {
        if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text)
                .then(() => alert("Copiado para a área de transferência!"))
                .catch(err => alert("Falha ao copiar: " + err));
        } else if (window.clipboardData && window.clipboardData.setData) {
            window.clipboardData.setData('Text', text);
            alert("Copiado para a área de transferência!");
        } else {
            alert("Falha ao copiar para a área de transferência! Clipboard API não disponível.");
        }
    },

    escapeHTML: (text) => {
        let element = document.createElement('p');
        element.textContent = text;
        return element.innerHTML;
    },

    getIP: () => rsg.ip,
    getPort: () => parsePortOrDefault(rsg.port),
    getShell: () => rsg.shell,
    getEncoding: () => rsg.encoding,

    getSelectedCommandName: () => {
        return rsg.selectedValues[rsg.commandType];
    },

    getReverseShellCommand: () => {
        if (typeof rsgData === 'undefined' || !rsgData.reverseShellCommands) return '';
        const reverseShellData = rsgData.reverseShellCommands.find((item) => item.name === rsg.getSelectedCommandName());
        return reverseShellData ? reverseShellData.command : '';
    },

    getPayload: () => {
        if (rsg.commandType === 'MSFVenom') {
            let cmd = rsg.getReverseShellCommand();
            let regex = /\s+-p\s+(?<payload>[a-zA-Z0-9/_]+)/;
            let match = regex.exec(cmd);
            if (match) {
                return match.groups.payload;
            }
        }
        return 'windows/x64/meterpreter/reverse_tcp';
    },

    getType: () => {
        if (rsg.commandType === 'HoaxShell') {
            let cmd_name = rsg.getSelectedCommandName();
            return hoaxshell_listener_types[cmd_name] || 'cmd-curl';
        }
        return 'cmd-curl';
    },

    generateReverseShellCommand: () => {
        let command;
        if (typeof rsgData === 'undefined') return '';

        if (rsg.getSelectedCommandName() === 'PowerShell #3 (Base64)' && rsgData.specialCommands && rsgData.specialCommands['PowerShell payload']) {
            const encoder = (text) => text;
            const payload = rsg.insertParameters(rsgData.specialCommands['PowerShell payload'], encoder);
            command = "powershell -e " + btoa(toBinary(payload));
            function toBinary(string) {
                const codeUnits = new Uint16Array(string.length);
                for (let i = 0; i < codeUnits.length; i++) {
                    codeUnits[i] = string.charCodeAt(i);
                }
                const charCodes = new Uint8Array(codeUnits.buffer);
                let result = '';
                for (let i = 0; i < charCodes.byteLength; i++) {
                    result += String.fromCharCode(charCodes[i]);
                }
                return result;
            }
        } else {
            command = rsg.getReverseShellCommand();
        }

        const encoding = rsg.getEncoding();
        if (encoding === 'Base64') {
            command = rsg.insertParameters(command, (text) => text);
            command = btoa(command);
        } else {
            function encoder(string) {
                let result = string;
                switch (encoding) {
                    case 'encodeURLDouble':
                        result = fixedEncodeURIComponent(result);
                    case 'encodeURL':
                        result = fixedEncodeURIComponent(result);
                        break;
                }
                return result;
            }
            command = rsg.escapeHTML(encoder(command));
            command = rsg.insertParameters(rsg.highlightParameters(command, encoder), encoder);
        }
        return command;
    },

    highlightParameters: (text, encoder) => {
        const parameters = ['{ip}', '{port}', '{shell}', encodeURI('{ip}'), encodeURI('{port}'), encodeURI('{shell}')];
        parameters.forEach((param) => {
            let encodedParam = encoder ? encoder(param) : param;
            text = text.replace(new RegExp(param.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), `<span class="highlighted-parameter">${encodedParam}</span>`);
        });
        return text;
    },

    init: () => {
        if (typeof rsgData === 'undefined') {
            console.error("rsgData not loaded. RSG cannot initialize.");
            return;
        }
        // Initialize selectedValues based on filtered data
        rsg.selectedValues = {
            [CommandType.ReverseShell]: filterCommandData(rsgData.reverseShellCommands, { commandType: CommandType.ReverseShell })[0]?.name || '',
            [CommandType.BindShell]: filterCommandData(rsgData.reverseShellCommands, { commandType: CommandType.BindShell })[0]?.name || '',
            [CommandType.MSFVenom]: filterCommandData(rsgData.reverseShellCommands, { commandType: CommandType.MSFVenom })[0]?.name || '',
            [CommandType.HoaxShell]: filterCommandData(rsgData.reverseShellCommands, { commandType: CommandType.HoaxShell })[0]?.name || '',
        };

        rsg.initListenerSelection();
        rsg.initShells();
        rsg.update(); // Initial update after selectors are ready
    },

    initListenerSelection: () => {
        if (!rsgListenerSelect || typeof rsgData === 'undefined' || !rsgData.listenerCommands) return;
        rsgListenerSelect.innerHTML = ''; // Clear previous options
        rsgData.listenerCommands.forEach((listenerData) => {
            const type = listenerData[0];
            const command = listenerData[1];
            const option = document.createElement("option");
            option.value = command;
            option.selected = rsg.listener === option.value;
            option.classList.add("listener-option");
            option.innerText = type;
            rsgListenerSelect.appendChild(option);
        });
    },

    initShells: () => {
        if (!rsgShellSelect || typeof rsgData === 'undefined' || !rsgData.shells) return;
        rsgShellSelect.innerHTML = ''; // Clear previous options
        rsgData.shells.forEach((shell) => {
            const option = document.createElement("option");
            option.selected = rsg.shell === shell;
            option.classList.add("shell-option");
            option.innerText = shell;
            rsgShellSelect.appendChild(option);
        });
    },

    setState: (newState = {}) => {
        Object.keys(newState).forEach((key) => {
            const value = newState[key];
            rsg[key] = value;
            localStorage.setItem(key, value);
        });
        Object.assign(rsg, newState);
        rsg.update();
    },

    insertParameters: (command, encoder) => {
        if (!command) return '';
        return command
            .replaceAll(encoder('{ip}'), encoder(rsg.getIP()))
            .replaceAll(encoder('{port}'), encoder(String(rsg.getPort())))
            .replaceAll(encoder('{shell}'), encoder(rsg.getShell()));
    },

    update: () => {
        if (typeof rsgData === 'undefined' || !rsgListenerSelect) {
            // If selectors are not ready (e.g. tab not active), defer update
            return;
        }
        rsg.updateListenerCommand();
        rsg.updateTabList();
        rsg.updateReverseShellCommand();
        rsg.updateValues();
    },

    updateValues: () => {
        if (!rsgListenerSelect || !rsgShellSelect || !rsgEncodingSelect || !rsgIpInput || !rsgPortInput || !rsgOperatingSystemSelect || !rsgSearchBox) return;
        
        const listenerOptions = rsgListenerSelect.querySelectorAll(".listener-option");
        listenerOptions.forEach((option) => { option.selected = rsg.listener === option.value; });

        const shellOptions = rsgShellSelect.querySelectorAll(".shell-option");
        shellOptions.forEach((option) => { option.selected = rsg.shell === option.value; });

        const encodingOptions = rsgEncodingSelect.querySelectorAll("option");
        encodingOptions.forEach((option) => { option.selected = rsg.encoding === option.value; });

        rsgIpInput.value = rsg.ip;
        rsgPortInput.value = rsg.port;
        rsgOperatingSystemSelect.value = rsg.filterOperatingSystem;
        rsgSearchBox.value = rsg.filterText;
    },

    updateTabList: () => {
        if (typeof rsgData === 'undefined' || !rsgData.reverseShellCommands || !rsg.uiElements[rsg.commandType]) return;
        const listSelectionSelector = rsg.uiElements[rsg.commandType].listSelection;
        const listSelectionElement = document.querySelector(listSelectionSelector);
        if (!listSelectionElement) return;

        const data = rsgData.reverseShellCommands;
        const filteredItems = filterCommandData(
            data,
            { filterOperatingSystem: rsg.filterOperatingSystem, filterText: rsg.filterText, commandType: rsg.commandType }
        );

        const documentFragment = document.createDocumentFragment();
        if (filteredItems.length === 0) {
            const emptyMessage = document.createElement("button");
            emptyMessage.innerText = "No results found";
            emptyMessage.classList.add("list-group-item", "list-group-item-action", "disabled");
            documentFragment.appendChild(emptyMessage);
        } else {
             // Ensure selectedValue is valid, otherwise pick the first one
            if (!filteredItems.find(item => item.name === rsg.selectedValues[rsg.commandType])) {
                rsg.selectedValues[rsg.commandType] = filteredItems[0]?.name || '';
            }
        }

        filteredItems.forEach((item) => {
            const { name } = item;
            const selectionButton = document.createElement("button");
            if (rsg.getSelectedCommandName() === item.name) {
                selectionButton.classList.add("active");
            }
            selectionButton.innerText = name;
            selectionButton.classList.add("list-group-item", "list-group-item-action");
            selectionButton.addEventListener("click", () => {
                rsg.selectedValues[rsg.commandType] = name;
                rsg.update();
            });
            documentFragment.appendChild(selectionButton);
        });
        listSelectionElement.replaceChildren(documentFragment);
    },

    updateListenerCommand: () => {
        if (!rsgListenerSelect || !rsgListenerCommand) return;
        const privilegeWarning = document.querySelector("#port-privileges-warning"); // Assuming this is in the main HTML
        let command = rsgListenerSelect.value;
        command = rsg.highlightParameters(command);
        command = command.replace('{port}', rsg.getPort());
        command = command.replace('{ip}', rsg.getIP());
        command = command.replace('{payload}', rsg.getPayload());
        command = command.replace('{type}', rsg.getType());

        if (privilegeWarning) {
            if (rsg.getPort() < 1024) {
                privilegeWarning.style.visibility = "visible";
                command = `<span class="highlighted-warning">sudo</span> ${command}`;
            } else {
                privilegeWarning.style.visibility = "hidden";
            }
        }
        rsgListenerCommand.innerHTML = command;
    },

    updateReverseShellSelection: () => {
        if (!rsg.uiElements[rsg.commandType]) return;
        const listSelectionSelector = rsg.uiElements[rsg.commandType].listSelection;
        const listSelectionElement = document.querySelector(listSelectionSelector);
        if (!listSelectionElement) return;

        let currentActive = listSelectionElement.querySelector(".list-group-item.active");
        if(currentActive) currentActive.classList.remove("active");
        
        const elements = Array.from(listSelectionElement.querySelectorAll(".list-group-item"));
        const selectedElement = elements.find((item) => item.innerText === rsg.getSelectedCommandName());
        if(selectedElement) selectedElement.classList.add("active");
    },

    updateReverseShellCommand: () => {
        if (!rsg.uiElements[rsg.commandType]) return;
        const commandSelector = rsg.uiElements[rsg.commandType].command;
        const commandElement = document.querySelector(commandSelector);
        if (!commandElement) return;

        const command = rsg.generateReverseShellCommand();
        commandElement.innerHTML = command;
    }
};

// Defer initialization until the specific tab is activated.
// The main HTML's tab switching logic should call rsgMainInit() when 'reverse' tab is shown.
let rsgInitialized = false;
function rsgMainInit() {
    if (rsgInitialized) return;
    initializeRSGSelectors();
    if (typeof rsgData !== 'undefined' && rsgListenerSelect) { // Check if rsgData and key selectors are available
        rsg.init();
        rsgInitialized = true;
        console.log("RSG Initialized for Reverse Shell tab.");
    } else {
        console.error("RSG Initialization failed: rsgData or essential selectors not found.");
    }
}

