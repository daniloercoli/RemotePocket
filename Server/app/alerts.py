"""Prometheus rules live in monitoring/alert-rules.yml, loaded by Prometheus itself.

The application only emits metrics. Deploy the supplied Prometheus/Alertmanager
configuration with a real scrape target and an operations receiver; it does not
send notifications or install monitoring services automatically.

Questo programma è software libera: puoi ridistribuirlo e/o modificarlo
sotto i termini della GNU General Public License come pubblicata dalla
Free Software Foundation, versione 3 della Licenza o (a propria scelta)
qualsiasi versione successiva.

Questo programma è distribuito nella speranza che sia utile, ma SENZA
ALCUNA GARANZIA; senza neppure la garanzia implicita di COMMERCIABILITÀ
o IDONEITÀ PER UNO SCOPO PARTICOLARE. Vedere la GNU General Public License
per dettagli.

Dovresti aver ricevuto una copia della GNU General Public License
insieme a questo programma. Se non è così, vedere <https://www.gnu.org/licenses/>.
"""
