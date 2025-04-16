function drawGraph(graphData) {
    var container = document.getElementById('mynetwork');
    var nodes = new vis.DataSet(graphData.nodes);
    var edges = new vis.DataSet(graphData.edges);
    var data = {
        nodes: nodes,
        edges: edges
    };

    console.log("Drawing graph...");
    var options = {
        // --- Node Styles ---
        nodes: {
            shape: 'box',       // Rectangular nodes are common for basic blocks
            color: '#F0F0F0',    // Light grey background
            margin: 10,         // Padding inside the node box
            // widthConstraint: { minimum: 100, maximum: 300 }, // Optional: control node width
            font: {
                size: 12,        // Slightly smaller font might fit better
                multi: true,     // Handle \n for multiline labels
                color: 'black',
                face: 'monospace', // Monospace is good for code/addresses
                align: 'left',   // Align text to the left within the node
                bold: {
                    color: '#C00000', // Red for highlighted parts (using <b> tag)
                    // face: 'monospace', // Inherits
                    // size: 12,       // Inherits
                }
            }
        },

        // --- Edge Styles ---
        edges: {
            arrows: {
                to: {
                    enabled: true,  // Show arrows pointing to the destination node
                    scaleFactor: 0.7 // Adjust arrow size if needed
                }
            },
            color: {
                color: '#848484',      // Default edge color (grey)
                highlight: '#000000', // Darker color when edge is selected/hovered
                // inherit: false    // Usually false or 'from'/'to' for hierarchical
            },
            smooth: {
                enabled: true,      // Use smooth curves (often good for hierarchical)
                type: 'cubicBezier', // Default smooth type
                // Adjust roundness if needed (0 = straight lines essentially)
                roundness: 0.5
                // Alternative: force straight lines if preferred
                // enabled: false
            },
            font: { // Style for edge labels (like branch conditions)
                align: 'top',   // Position label above the edge
                size: 10,
                color: '#505050'
            }
        },

        // --- Layout Configuration ---
        layout: {
            hierarchical: {
                enabled: true,          // Enable the hierarchical layout engine
                direction: 'UD',        // Arrange nodes Up-Down (top to bottom)
                sortMethod: 'directed', // Crucial for CFGs: tries to minimize edge crossing
                                        // based on edge direction
                levelSeparation: 150,   // Vertical distance between levels
                nodeSpacing: 270,      // Horizontal distance between nodes *on the same level*
                treeSpacing: 200,      // Horizontal distance between distinct trees/subgraphs
                                        // (if the function has multiple disconnected parts)
                blockShifting: true,    // Allow shifting blocks to reduce edge length (usually good)
                edgeMinimization: true, // Try to minimize total edge length (usually good)
                parentCentralization: true // Center parent nodes above their children (usually good)
            }
        },

        // --- Interaction ---
        interaction: {
            dragNodes: true,         // Allow dragging nodes (useful even in hierarchical)
            dragView: true,          // Allow panning the view
            zoomView: true,          // Allow zooming
            navigationButtons: true, // Show UI buttons for zoom/fit
            keyboard: true,          // Enable keyboard navigation (arrows to pan)
            tooltipDelay: 200        // Delay before tooltips appear (if you add tooltips)
        },

        // --- Physics ---
        physics: {
            enabled: false // CRITICAL: Disable physics when using hierarchical layout
        }
    };

    console.log("Creating vis Network...");
    console.log
    var network = new vis.Network(container, data, options);
    console.log("Network created.");

    // Add keyboard event listener for hotkeys
    document.addEventListener('keydown', function(event) {
        // Only handle hotkeys if no input field is focused
        if (document.activeElement.tagName === 'INPUT') return;

        if (event.key === 'e' || event.key === 'E') {
            const selectedNodes = network.getSelectedNodes();
            if (selectedNodes.length === 1) {
                eel.enter_cfg(selectedNodes[0])(function (result) {                 
                    if (result !== null) {
                        window.network.destroy();
                        drawGraph(result);
                    }
                }); 
            }
        } else if (event.key === 'r' || event.key === 'R') {
            eel.exit_cfg()(function (result) {

                if (result !== null) {
                    window.network.destroy();
                    drawGraph(result);
                }
            });

        } else if (event.key === 'p' || event.key === 'P') {
            const selectedEdges = network.getSelectedEdges();
            if (selectedEdges.length === 1) {
                eel.print_path_condition(selectedEdges[0])(function(condition) {
                    if (condition) {
                        showPathCondition(condition);
                    }
                });
            }
        }
    });
    window.network = network;
}

function toggleTaintOptions() {
    const taintType = document.getElementById('taint-type').value;
    const offsetGroup = document.getElementById('offset-group');
    const sizeGroup = document.getElementById('size-group');
    const targetInput = document.getElementById('taint-target');
    const sizeInput = document.getElementById('taint-size');
    const sizeMultiplierInput = document.getElementById('taint-size-multiplier');
    const offsetInput = document.getElementById('taint-offset');


    if (taintType === 'register') {
        offsetGroup.style.display = 'none';
        sizeGroup.style.display = 'none';
        targetInput.value = '';
        offsetInput.value = '0';
        sizeInput.value = '';
        sizeMultiplierInput.value = '';
        targetInput.placeholder = 'e.g., rax';

    } else if (taintType === 'memory') {
        offsetGroup.style.display = 'none'; 
        offsetInput.value = '0';
        targetInput.value = '';
        sizeGroup.style.display = 'block';
        targetInput.placeholder = 'e.g., 0x7fffffffe100';
        sizeInput.placeholder = 'e.g., 8 OR rcx';
        sizeMultiplierInput.placeholder = 'e.g., 4';
    } else if (taintType === 'relative_memory') {
        offsetGroup.style.display = 'block';
        sizeGroup.style.display = 'block';
        targetInput.value = '';        
        targetInput.placeholder = 'e.g., rdi';
        sizeInput.placeholder = 'e.g., 8 OR rcx';
        sizeMultiplierInput.placeholder = 'e.g., 4';
    }
}

function renderRulesList(rules) {
    const rulesList = document.getElementById('rules-list');
    rulesList.innerHTML = ''; 
    currentTaintRules = rules;



    rules.forEach((rule, index) => {
        const li = document.createElement('li');
        let details = `${rule.address_str} | ${rule.type} | ${rule.target_str}`;
        if (rule.type === 'relative_memory') {
            details += ` | offset: ${rule.offset || 0}`;
        }
         if (rule.type === 'memory' || rule.type === 'relative_memory') {
            details += ` | size: ${rule.size_str} | mult: ${rule.sizeMultiplier}`;
        }

        li.textContent = details + ' '; // Add space before button

        const deleteButton = document.createElement('button');
        deleteButton.textContent = 'Delete';
        deleteButton.classList.add('delete-btn');
        // Store rule ID on the button for easy deletion
        deleteButton.dataset.ruleId = rule.id;

        deleteButton.onclick = function() {
            const idToDelete = parseInt(this.dataset.ruleId);
            console.log(`Requesting deletion of rule ID: ${idToDelete}`);
            // Call python to delete, then re-render list in the callback
            eel.delete_taint_rule(idToDelete)(renderRulesList);
        };

        li.appendChild(deleteButton);
        rulesList.appendChild(li);
    });
}

function showError(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    setTimeout(() => {
        errorDiv.style.display = 'none';
    }, 5000); // Hide error after 5 seconds
}

function showPathCondition(condition) {
    const box = document.getElementById('path-condition-box');
    const content = document.getElementById('path-condition-content');
    content.textContent = condition;
    box.style.display = 'block';
}

function hidePathCondition() {
    const box = document.getElementById('path-condition-box');
    box.style.display = 'none';
}

function copyPathCondition() {
    const content = document.getElementById('path-condition-content');
    navigator.clipboard.writeText(content.textContent)
        .then(() => {
            const button = document.getElementById('copy-path-condition');
            const originalText = button.textContent;
            button.textContent = 'Copied!';
            setTimeout(() => {
                button.textContent = originalText;
            }, 2000);
        })
        .catch(err => {
            console.error('Failed to copy text: ', err);
        });
}

window.onload = function() {
    console.log("Requesting graph data from Python...");

    eel.get_graph_data()(drawGraph);    


    const taintTypeSelect = document.getElementById('taint-type');
    taintTypeSelect.addEventListener('change', toggleTaintOptions);

    const addRuleForm = document.getElementById('add-rule-form');
    addRuleForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const formData = {
            address: document.getElementById('trigger-address').value.trim(),
            type: document.getElementById('taint-type').value,
            target: document.getElementById('taint-target').value.trim(),
            offset: document.getElementById('taint-offset').value.trim(),
            size: document.getElementById('taint-size').value.trim(),
            sizeMultiplier: document.getElementById('taint-size-multiplier').value.trim()
        };

        eel.add_taint_rule(formData)(function(rules) {
            if (typeof rules == 'string') {
                showError(rules);
            } else {
                renderRulesList(rules);
                console.log("Taint rules updated.");
                // Clear form
                document.getElementById('add-rule-form').reset();
                document.getElementById('offset-group').style.display = 'none';
                document.getElementById('size-group').style.display = 'none';
            }
        });
    });   
    console.log("Adding analysis button listener...");
    const analysisButton = document.getElementById('start-analysis-btn');
    analysisButton.addEventListener('click', function() {
        console.log("Starting analysis...");
        window.network.destroy();
        console.log("Network destroyed");
        eel.start_analysis()(drawGraph); // Call the Python analysis function
    });       

    // Add event listeners for path condition box
    document.getElementById('close-path-condition').addEventListener('click', hidePathCondition);
    document.getElementById('copy-path-condition').addEventListener('click', copyPathCondition);
}; 
