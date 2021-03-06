package ru.ispras.lingvodoc.frontend.app.controllers.webui.modal

import com.greencatsoft.angularjs.core.{ExceptionHandler, Scope, Timeout}
import com.greencatsoft.angularjs.extensions.{ModalInstance, ModalService}
import com.greencatsoft.angularjs.{AngularExecutionContextProvider, injectable}
import org.scalajs.dom.console
import ru.ispras.lingvodoc.frontend.app.controllers.base.BaseModalController
import ru.ispras.lingvodoc.frontend.app.controllers.common.DictionaryTable
import ru.ispras.lingvodoc.frontend.app.controllers.traits.{LinkEntities, SimplePlay, ViewMarkup}
import ru.ispras.lingvodoc.frontend.app.exceptions.ControllerException
import ru.ispras.lingvodoc.frontend.app.model._
import ru.ispras.lingvodoc.frontend.app.services.{BackendService, UserService}
import ru.ispras.lingvodoc.frontend.app.utils.Utils

import scala.concurrent.Future
import scala.scalajs.js
import scala.scalajs.js.annotation.JSExport
import scala.util.{Failure, Success}


@js.native
trait ContributionsLinkedDictionaryModalScope extends Scope {
  var linkedPath: String = js.native
  var dictionaryTable: DictionaryTable = js.native
  var count: Int = js.native
  var offset: Int = js.native
  var size: Int = js.native
  var pageCount: Int = js.native
}


@injectable("ContributionsLinkedDictionaryModalController")
class ContributionsLinkedDictionaryModalController(scope: ContributionsLinkedDictionaryModalScope,
                                             val modal: ModalService,
                                             instance: ModalInstance[Unit],
                                                   val backend: BackendService,
                                             userService: UserService,
                                             timeout: Timeout,
                                             val exceptionHandler: ExceptionHandler,
                                             params: js.Dictionary[js.Function0[js.Any]])
  extends BaseModalController(scope, modal, instance, timeout, params)
    with AngularExecutionContextProvider
    with SimplePlay
    with LinkEntities
    with ViewMarkup {

  protected[this] val dictionaryId: CompositeId = params("dictionaryId").asInstanceOf[CompositeId]
  protected[this] val perspectiveId: CompositeId = params("perspectiveId").asInstanceOf[CompositeId]
  private[this] val field = params("field").asInstanceOf[Field]
  private[this] val entities = params("entities").asInstanceOf[js.Array[Entity]]

  private[this] val linkPerspectiveId = field.link.map { link =>
    CompositeId(link.clientId, link.objectId)
  }.ensuring(_.nonEmpty, "Field has no linked perspective!").get

  private[this] var perspectiveTranslation: Option[TranslationGist] = None


  scope.count = 0
  scope.offset = 0
  scope.size = 20

  private[this] var dataTypes = Seq[TranslationGist]()
  private[this] var perspectiveFields = Seq[Field]()
  private[this] var linkedPerspectiveFields = Seq[Field]()

  override def spectrogramId: String = "#spectrogram-modal"

  @JSExport
  def dataTypeString(dataType: TranslationGist): String = {
    dataType.atoms.find(a => a.localeId == 2) match {
      case Some(atom) =>
        atom.content
      case None => throw new ControllerException("")
    }
  }

  @JSExport
  def linkedPerspectiveName(): String = {
    perspectiveTranslation match {
      case Some(gist) =>
        val localeId = Utils.getLocale().getOrElse(2)
        gist.atoms.find(_.localeId == localeId) match {
          case Some(atom) => atom.content
          case None => ""
        }
      case None => ""
    }
  }

  private[this] def linkEntity(entry: LexicalEntry): Option[Entity] = {
    entities.find(entity => entity.link.exists(link => link.clientId == entry.clientId && link.objectId == entry.objectId))
  }

  @JSExport
  def accept(entry: LexicalEntry): Unit = {
    linkEntity(entry) foreach { entity =>
      if (!entity.accepted) {
        backend.acceptEntities(dictionaryId, perspectiveId, CompositeId.fromObject(entity) :: Nil) map { _ =>
          scope.$apply(() => {
            entity.accepted = true
          })
        }
      }
    }
  }

  @JSExport
  def acceptDisabled(entry: LexicalEntry): Boolean = {
    linkEntity(entry).exists(_.accepted)
  }

  @JSExport
  def close(): Unit = {
    instance.close(())
  }

  load(() => {

    backend.perspectiveSource(linkPerspectiveId) onComplete {
      case Success(sources) =>
        scope.linkedPath = sources.reverse.map { _.source match {
          case language: Language => language.translation
          case dictionary: Dictionary => dictionary.translation
          case perspective: Perspective => perspective.translation
        }}.mkString(" >> ")
      case Failure(e) => console.error(e.getMessage)
    }

    backend.getPerspective(perspectiveId) map {
      p =>
        backend.translationGist(CompositeId(p.translationGistClientId, p.translationGistObjectId)) map {
          gist =>
            perspectiveTranslation = Some(gist)
        }
    }

    backend.dataTypes() map { allDataTypes =>
      dataTypes = allDataTypes
      // get fields of main perspective
      backend.getFields(dictionaryId, perspectiveId) map { fields =>
        perspectiveFields = fields
        // get fields of this perspective
        backend.getFields(dictionaryId, linkPerspectiveId) map { linkedFields =>
          linkedPerspectiveFields = linkedFields
          val reqs =  entities.flatMap(_.link).toSeq.map { link =>
            backend.getLexicalEntry(dictionaryId, linkPerspectiveId, CompositeId(link.clientId, link.objectId)) map { entry =>
              Option(entry)
            } recover { case e: Throwable =>
              Option.empty[LexicalEntry]
            }
          }
          Future.sequence(reqs) map { lexicalEntries =>
            scope.dictionaryTable = DictionaryTable.build(linkedFields, dataTypes, lexicalEntries.flatten)
          } recover {
            case e: Throwable => error(e)
          }
        } recover {
          case e: Throwable => error(e)
        }
      } recover {
        case e: Throwable => error(e)
      }
    } recover {
      case e: Throwable => error(e)
    }
  })


  override protected def onModalClose(): Unit = {
    waveSurfer.foreach( w => w.destroy())
    super.onModalClose()
  }

  override protected def onStartRequest(): Unit = {}

  override protected def onCompleteRequest(): Unit = {}

  override protected[this] def dictionaryTable: DictionaryTable = scope.dictionaryTable
}

