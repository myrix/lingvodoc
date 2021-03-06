package ru.ispras.lingvodoc.frontend.app.controllers.webui

import com.greencatsoft.angularjs.{AbstractController, AngularExecutionContextProvider, injectable}
import com.greencatsoft.angularjs.core.{ExceptionHandler, Scope, Timeout}
import io.plasmap.pamphlet._
import ru.ispras.lingvodoc.frontend.app.controllers.SearchQuery
import ru.ispras.lingvodoc.frontend.app.controllers.common.{DictionaryTable, Value}
import ru.ispras.lingvodoc.frontend.app.controllers.traits.{LoadingPlaceholder, SimplePlay}
import ru.ispras.lingvodoc.frontend.app.model._
import ru.ispras.lingvodoc.frontend.app.services.BackendService
import com.greencatsoft.angularjs.extensions.{ModalOptions, ModalService, ModalInstance}

import scala.concurrent.Future
import scala.scalajs.js
import scala.scalajs.js.UndefOr
import scala.scalajs.js.annotation.{JSExport, JSExportAll}
import scala.util.Random
import scala.scalajs.js.JSConverters._


@JSExportAll
case class Query(var question: String, var answer: String)


@js.native
trait SociolinguisticsScope extends Scope {
  var adoptedSearch: String = js.native
  var etymologySearch: String = js.native
  var search: js.Array[SearchQuery] = js.native
  var selectedPerspectives: js.Array[Perspective] = js.native
  //var searchResults: js.Array[DictionaryTable] = js.native
  var questions: js.Array[String] = js.native
  var answers: js.Array[String] = js.native
  var queries: js.Array[Query] = js.native
  var results: js.Array[SociolinguisticsEntry] = js.native
  var searchComplete: Boolean = js.native
  var progressBar: Boolean = js.native
}

@injectable("SociolinguisticsController")
class SociolinguisticsController(scope: SociolinguisticsScope, val backend: BackendService, modal: ModalService, val timeout: Timeout, val exceptionHandler: ExceptionHandler)
  extends AbstractController[SociolinguisticsScope](scope)
    with AngularExecutionContextProvider
    with SimplePlay
    with LoadingPlaceholder {

  private[this] var dictionaries = Seq[Dictionary]()
  private[this] var perspectives = Seq[Perspective]()
  private[this] var perspectivesMeta = Seq[PerspectiveMeta]()
  private[this] var dataTypes = Seq[TranslationGist]()
  private[this] var fields = Seq[Field]()
  private[this] var allMarkers = Seq[Marker]()
  private[this] var sociolinguisticsEntries = Seq[SociolinguisticsEntry]()

  // create map
  private[this] val leafletMap = createMap()
  private[this] val defaultIconOptions = IconOptions.iconUrl("static/images/marker-icon-default.png").iconSize(Leaflet.point(50, 41)).iconAnchor(Leaflet.point(13, 41)).build
  private[this] val defaultIcon = Leaflet.icon(defaultIconOptions)

  private[this] val selectedIconOptions = IconOptions.iconUrl("static/images/marker-icon-selected.png").iconSize(Leaflet.point(50, 41)).iconAnchor(Leaflet.point(13, 41)).build
  private[this] val selectedIcon = Leaflet.icon(selectedIconOptions)

  private[this] val resultIconOptions = IconOptions.iconUrl("static/images/marker-icon-selected.png").iconSize(Leaflet.point(100, 82)).iconAnchor(Leaflet.point(26, 82)).build
  private[this] val resultIcon = Leaflet.icon(resultIconOptions)
  private[this] val rng = Random


  // scope initialization
  scope.adoptedSearch = "unchecked"
  scope.etymologySearch = "unchecked"
  scope.search = js.Array(SearchQuery())
  scope.selectedPerspectives = js.Array[Perspective]()
  scope.questions = js.Array[String]()
  scope.answers = js.Array[String]()
  scope.queries = js.Array[Query](Query("", ""))
  scope.results = js.Array[SociolinguisticsEntry]()
  scope.searchComplete = false
  scope.progressBar = false

  private[this] def showInfo(sociolinguisticsEntry: SociolinguisticsEntry) = {

    val options = ModalOptions()
    options.templateUrl = "/static/templates/modal/viewSociolinguisticsInfo.html"
    options.controller = "ViewSociolinguisticsInfoController"
    options.backdrop = false
    options.keyboard = false
    options.size = "lg"
    options.resolve = js.Dynamic.literal(
      params = () => {
        js.Dynamic.literal(entry = sociolinguisticsEntry.asInstanceOf[js.Object])
      }).asInstanceOf[js.Dictionary[Any]]
    val instance = modal.open[Unit](options)
  }

  @JSExport
  def addQuery(): Unit = {
    scope.queries.push(Query("", ""))
  }

  @JSExport
  def doSearch() = {
    allMarkers.foreach(m => leafletMap.removeLayer(m))
    allMarkers = Seq[Marker]()
    scope.results = js.Array[SociolinguisticsEntry]()
    val qs = scope.queries.filter(q => q.answer.nonEmpty && q.question.nonEmpty).map(q => (q.question, q.answer)).toSeq.toMap
    scope.results = sociolinguisticsEntries.filter { e =>
      qs.forall{case (q, a) =>
        e.questions.exists{ t =>
          t._1 == q && t._2 == a
        }
      }
    }.toJSArray
    highlightSearchResults(scope.results)
    scope.searchComplete = true
  }

  @JSExport
  def reset(): Unit = {
    scope.results = js.Array[SociolinguisticsEntry]()
    allMarkers.foreach(m => leafletMap.removeLayer(m))
    allMarkers = Seq[Marker]()
    scope.queries = js.Array(Query("", ""))
    addAllMarkers()
    scope.searchComplete = false
  }

  private[this] def addAllMarkers(): Unit = {
    sociolinguisticsEntries.foreach(e => addMarker(e))
  }

  private[this] def highlightSearchResults(results: Seq[SociolinguisticsEntry]): Unit = {
    results.foreach{ entry =>
      addMarker(entry)
    }
  }

  private[this] def addMarker(entry: SociolinguisticsEntry): Unit = {

    val latLng = entry.location
    val markerOptions = js.Dynamic.literal("icon" -> defaultIcon).asInstanceOf[MarkerOptions]
    // TODO: Add support for marker cluster
    val p = if (allMarkers.exists(p => p.getLatLng().lat == latLng.lat && p.getLatLng().lng == latLng.lng)) {
      val latK = (-0.005) + (0.005 - (-0.005)) * rng.nextDouble
      val lngK = (-0.005) + (0.005 - (-0.005)) * rng.nextDouble
      Leaflet.latLng(latLng.lat + latK, latLng.lng + lngK)
    } else {
      Leaflet.latLng(latLng.lat, latLng.lng)
    }

    val marker: Marker = Leaflet.marker(p, markerOptions).asInstanceOf[Marker]

    // prevents context menu from showing
    marker.on("contextmenu", (e: js.Any) => {

    })

    // marker click handler
    marker.onMouseDown(e => {
      e.originalEvent.button match {
        // left button click
        case 0 =>
          showInfo(entry)
        // right button click
        case 2 =>

      }
    })

    allMarkers = allMarkers :+ marker
    marker.addTo(leafletMap)
  }

  private[this] def createMap(): LeafletMap = {
    // map object initialization
    val cssId = "sociolinguisticsMap"
    val conf = LeafletMapOptions.zoomControl(true).scrollWheelZoom(true).build
    val leafletMap = Leaflet.map(cssId, conf)
    val MapId = "lingvodoc_ispras_ru"
    val Attribution = "Map data &copy; <a href=\"http://openstreetmap.org\">OpenStreetMap</a> contributors, <a href=\"http://creativecommons.org/licenses/by-sa/2.0/\">CC-BY-SA</a>, Imagery © <a href=\"http://mapbox.com\">Mapbox</a>"

    // 61.5240° N, 105.3188° E
    val x = 61.5240f
    val y = 105.3188f
    val z = 3

    val uri = s"http://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
    val tileLayerOptions = TileLayerOptions
      .attribution(Attribution)
      .subdomains(scalajs.js.Array("a", "b", "c"))
      .mapId(MapId)
      .detectRetina(true).build

    val tileLayer = Leaflet.tileLayer(uri, tileLayerOptions)
    tileLayer.addTo(leafletMap)
    leafletMap.setView(Leaflet.latLng(x, y), z)
    leafletMap
  }

  override protected def onLoaded[T](result: T): Unit = {}

  override protected def onError(reason: Throwable): Unit = {}

  override protected def preRequestHook(): Unit = {}

  override protected def postRequestHook(): Unit = {


  }

  doAjax(() => {
    // load list of data types
    backend.dataTypes() flatMap { d =>
      dataTypes = d
      // load list of fields
      backend.fields() flatMap { f =>
        fields = f.toJSArray

        backend.getDictionaries(DictionaryQuery()) flatMap { d =>
          dictionaries = d
          backend.perspectives() flatMap { p =>
            perspectives = p
            backend.allPerspectivesMeta flatMap { pm =>
              perspectivesMeta = pm
              backend.sociolinguistics() flatMap { s =>
                sociolinguisticsEntries = s
                backend.sociolinguisticsQuestions() flatMap { questions =>
                  scope.questions = questions.toJSArray
                  backend.sociolinguisticsAnswers() map { answers =>
                    scope.answers = answers.toJSArray
                    addAllMarkers
                  }
                }
              }

            }
          }
        }
      }
    }
  })
}