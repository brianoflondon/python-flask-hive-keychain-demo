// const search = document.getElementById('acc-name');
const search2 = document.getElementById('myInput');
// const matchlist = document.getElementById('match-list');

// search.addEventListener('input', () => searchHiveNames(search.value));
// search2.addEventListener('input', () => searchHiveNames2(search2.value));

// search Hive api and filter

// const searchHiveNames = async searchText => {
//     console.log(searchText)
//     const res = await fetch("https://api.hive.blog", {
//         body: `{"jsonrpc":"2.0", "method":"database_api.list_accounts", "params": {"start":"${searchText}", "limit":3, "order":"by_name"}, "id":1}`,
//         headers: {
//           "Content-Type": "application/x-www-form-urlencoded"
//         },
//         method: "POST"
//       });
//     var rawData = await res.json();
//     var accNames = rawData.result.accounts;
//     if(searchText.length === 0) {
//         accNames = [];
//         matchlist.innerHTML = '';
//     };
//     console.log(accNames);
//     outpuHtml(accNames);
// };

// const outpuHtml = accNames => {
//     if(accNames.length > 0 ) {
//         const html = accNames.map(accName => `
//         <div class="card card-body mb-1" id="choice-${accName.id}">
//             <a href="#"><h4>${accName.name}</h4></a>
//         </div>
//         `).join('');
//         matchlist.innerHTML = html;
//     }
// }



// Alternative system https://codepen.io/Sinnemanie/pen/LBZqEr

"use strict";

let autocomplete = (inp, arr) => {
  /*the autocomplete function takes two arguments,
  the text field element and an array of possible autocompleted values:*/
  let currentFocus;
  /*execute a function when someone writes in the text field:*/
  inp.addEventListener("input", function(e) {
    let a, //OUTER html: variable for listed content with html-content
      b, // INNER html: filled with array-Data and html
      i, //Counter
      val = this.value;
      arr = searchHiveNames2(inp.value);
    /*close any already open lists of autocompleted values*/
    closeAllLists();

    if (!val) {
      return false;
    }
    arr = searchHiveNames2(inp.value);
    currentFocus = -1;

    /*create a DIV element that will contain the items (values):*/
    a = document.createElement("DIV");

    a.setAttribute("id", this.id + "autocomplete-list");
    a.setAttribute("class", "autocomplete-items list-group text-left");

    /*append the DIV element as a child of the autocomplete container:*/
    this.parentNode.appendChild(a);

    /*for each item in the array...*/
    for (i = 0; i < arr.length; i++) {
      /*check if the item starts with the same letters as the text field value:*/
      if (arr[i].substr(0, val.length).toUpperCase() == val.toUpperCase()) {
        /*create a DIV element for each matching element:*/
        b = document.createElement("DIV");
        b.setAttribute("class","list-group-item list-group-item-action");
        /*make the matching letters bold:*/
        b.innerHTML = "<strong>" + arr[i].substr(0, val.length) + "</strong>";
        b.innerHTML += arr[i].substr(val.length);
        /*insert a input field that will hold the current array item's value:*/
        b.innerHTML += "<input type='hidden' value='" + arr[i] + "'>";
        /*execute a function when someone clicks on the item value (DIV element):*/
        b.addEventListener("click", function(e) {
          /*insert the value for the autocomplete text field:*/
          inp.value = this.getElementsByTagName("input")[0].value;
          /*close the list of autocompleted values,
              (or any other open lists of autocompleted values:*/
          closeAllLists();
        });
        a.appendChild(b);
      }
    }
  });

  /*execute a function presses a key on the keyboard:*/
  inp.addEventListener("keydown", function(e) {
    var x = document.getElementById(this.id + "autocomplete-list");
    if (x) x = x.getElementsByTagName("div");
    if (e.keyCode == 40) {
      /*If the arrow DOWN key is pressed,
        increase the currentFocus variable:*/
      currentFocus++;
      /*and and make the current item more visible:*/
      addActive(x);
    } else if (e.keyCode == 38) {
      //up
      /*If the arrow UP key is pressed,
        decrease the currentFocus variable:*/
      currentFocus--;
      /*and and make the current item more visible:*/
      addActive(x);
    } else if (e.keyCode == 13) {
      /*If the ENTER key is pressed, prevent the form from being submitted,*/
      e.preventDefault();
      if (currentFocus > -1) {
        /*and simulate a click on the "active" item:*/
        if (x) x[currentFocus].click();
      }
    }
  });

  let addActive = (x) => {
    /*a function to classify an item as "active":*/
    if (!x) return false;
    /*start by removing the "active" class on all items:*/
    removeActive(x);
    if (currentFocus >= x.length) currentFocus = 0;
    if (currentFocus < 0) currentFocus = x.length - 1;
    /*add class "autocomplete-active":*/
    x[currentFocus].classList.add("active");
  }

  let removeActive = (x) => {
    /*a function to remove the "active" class from all autocomplete items:*/
    for (let i = 0; i < x.length; i++) {
      x[i].classList.remove("active");
    }
  }

  let closeAllLists = (elmnt) => {
    /*close all autocomplete lists in the document,
    except the one passed as an argument:*/
    var x = document.getElementsByClassName("autocomplete-items");
    for (var i = 0; i < x.length; i++) {
      if (elmnt != x[i] && elmnt != inp) {
        x[i].parentNode.removeChild(x[i]);
      }
    }
  }

  /*execute a function when someone clicks in the document:*/
  document.addEventListener("click", function(e) {
    closeAllLists(e.target);
  });
};



let countries =['brianoflondon','adamcurry']
/*initiate the autocomplete function on the "myInput" element, and pass along the countries array as possible autocomplete values:*/

const searchHiveNames2 = async searchText => {
    console.log(searchText)
    const res = await fetch("https://api.hive.blog", {
        body: `{"jsonrpc":"2.0", "method":"database_api.list_accounts", "params": {"start":"${searchText}", "limit":10, "order":"by_name"}, "id":1}`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        method: "POST"
      });
    var rawData = await res.json();
    var accNames = rawData.result.accounts;
    var arr = []
    for (i = 0; i < accNames.length; i++) {
        arr[i] = accNames[i].name;
    };
    if(searchText.length === 0) {
        accNames = [];
    };
    console.log(arr);
    return arr;
};


autocomplete(search2, searchHiveNames2(search2.value));
