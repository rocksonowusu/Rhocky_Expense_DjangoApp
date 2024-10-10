    const searchField = document.querySelector('#searchField');
    const tableOutput = document.querySelector(".table-output");
    const appTable = document.querySelector(".app-table");
    const paginationContainer = document.querySelector(".pagination-container");
    const tableBody = document.querySelector(".table-body");
  
    tableOutput.style.display = "none";
  
    searchField.addEventListener("keyup", (e) => {
        const searchValue = e.target.value.trim();
  
        if (searchValue.length > 0) {
            paginationContainer.style.display = "none";
            tableBody.innerHTML = "";
  
            fetch("/income/search_income", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ searchText: searchValue }),
            })
            .then((res) => {
                if (!res.ok) {
                    throw new Error(`HTTP error! Status: ${res.status}`);
                }
                return res.json();
            })
            .then((data) => {
                console.log("data", data);
  
                appTable.style.display = "none";
                tableOutput.style.display = "block";
  
                if (data.length === 0) {
                    tableOutput.innerHTML = "No results found";
                } else {
                    data.forEach((item) => {
                        tableBody.innerHTML += `
                        <tr>
                            <td>${item.amount}</td> 
                            <td>${item.source}</td> 
                            <td>${item.description}</td>
                            <td>${item.date}</td>
                        </tr>`;
                    });
                }
            })
            .catch((error) => {
                console.error("Error fetching data:", error);
            });
        } else {
            appTable.style.display = "block";
            paginationContainer.style.display = "block";
            tableOutput.style.display = "none";
        }
    });

  