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
      <form action="submit_nodes", method="POST">
        <table class="mdl-data-table mdl-js-data-table mdl-data-table--selectable mdl-shadow--2dp vertical-center">
          <thead>
            <tr>
              <th class="mdl-data-table__cell--non-numeric">Computer's name</th>
              <th>Address</th>
            </tr>
          </thead>
          <tbody>
            % index = 0
            % for node in known_nodes:
            <tr>
              <td class="mdl-data-table__cell--non-numeric" name={{index}} value={{node}}>{{node}}</td>
              <td>{{known_nodes[node]["last_known_address"]}}</td>
            </tr>
            % index += 1
            % end
         </tbody>
        </table>
        <div class="execute-button">
          <button class="mdl-button mdl-button--colored mdl-js-button mdl-js-ripple-effect" type="submit">Lets do it!</button>
        </div>
      </form>
    </div>
  </body>

</html>
