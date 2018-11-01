<html>

  <head>
    <title>NetDog [Select Nodes]</title>

    <!-- Material Design Lite -->
    <script src="https://code.getmdl.io/1.3.0/material.min.js"></script>
    <link rel="stylesheet" href="https://code.getmdl.io/1.3.0/material.indigo-pink.min.css">

    <!-- Material Design icon font -->
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">

    <!-- Roboto Font -->
    <link rel="stylesheet" href="http://fonts.googleapis.com/css?family=Roboto:300,400,500,700" type="text/css">

    <!-- Our own CSS -->
    <link rel="stylesheet" type="text/css" href="css/default.css">
  </head>

  <body>
    <div class="mdl-grid center-items">
      <table class="mdl-data-table mdl-js-data-table mdl-data-table--selectable mdl-shadow--2dp vertical-center">
        <thead>
          <tr>
            <th class="mdl-data-table__cell--non-numeric">Computer's name</th>
            <th>Address</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            % for node in known_nodes:
              <td class="mdl-data-table__cell--non-numeric">{{node}}</td>
              <td>{{known_nodes[node]["last_known_address"]}}</td>
          </tr>
       </tbody>
      </table>
      <div class="execute-button">
    <a class="mdl-button mdl-button--colored mdl-js-button mdl-js-ripple-effect">
      Lets do it!
    </a>
      </div>
    </div>
  </body>

</html>
