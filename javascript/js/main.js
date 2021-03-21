const search = document.getElementById('acc-name');
const nameList = document.getElementById('nameList');

search.addEventListener('input', () => searchHiveNames(search.value));

// search Hive api and filter

const searchHiveNames = async searchText => {
    console.log(searchText)
    const res = await fetch("https://api.hive.blog", {
        body: `{"jsonrpc":"2.0", "method":"database_api.list_accounts", "params": {"start":"${searchText}", "limit":3, "order":"by_name"}, "id":1}`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        method: "POST"
      });
    var rawData = await res.json();
    var accNames = rawData.result.accounts;
    if(searchText.length === 0) {
        accNames = [];
        nameList.innerHTML = '';
    };
    console.log(accNames);
    outpuHtml(accNames);
};

const outpuHtml = accNames => {
    if(accNames.length > 0 ) {
        const html = accNames.map(accName => `
        <div class="card card-body mb-1" id="choice-${accName.id}" onclick="elementSelected()">
            <h4>${accName.name}</h4>
        </div>
        `).join('');
        nameList.innerHTML = html;
    }
}

function elementSelected(){
    console.log('hello')
    // Dig from the event which element was
    // clicked and do something with it
  }

// fetch("https://api.hive.blog", {
//     body: `{"jsonrpc":"2.0", "method":"database_api.list_accounts", "params": {"start":"${aName}", "limit":10, "order":"by_name"}, "id":1}`,
//     headers: {
//       "Content-Type": "application/x-www-form-urlencoded"
//     },
//     method: "POST"
//   })
//     .then(res => res.json())
//     .then(ans => console.log(ans))


// https://kigiri.github.io/fetch/