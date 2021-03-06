package ru.ispras.lingvodoc.frontend.app.controllers.traits

import com.greencatsoft.angularjs.{AngularExecutionContextProvider, Controller}

import scala.concurrent.{ExecutionContext, Future}
import scala.scalajs.js
import scala.util.{Failure, Success}

@deprecated("Replaced with BaseController/BaseModalController", "2016-12-14")
trait LoadingPlaceholder extends AngularExecutionContextProvider {
  this: Controller[_] =>


  protected def onLoaded[T](result: T)
  protected def onError(reason: Throwable)

  protected def preRequestHook()
  protected def postRequestHook()

  protected def doAjax(load: () => Future[_]): Unit = {
    preRequestHook()
    load() onComplete {
      case Success(result) =>
        postRequestHook()
        onLoaded(result)
      case Failure(e) =>
        postRequestHook()
        onError(e)
    }
  }
}
