package ru.ispras.lingvodoc.frontend.app.controllers

import com.greencatsoft.angularjs.core._
import com.greencatsoft.angularjs.{AbstractController, AngularExecutionContextProvider, injectable}
import ru.ispras.lingvodoc.frontend.app.services.BackendService

import scala.scalajs.js
import scala.scalajs.js.annotation.JSExport
import scala.util.{Failure, Success}
import org.scalajs.dom.console



@js.native
trait LoginScope extends Scope {
  var username: String = js.native
  var password: String = js.native
  var remember: Boolean = js.native
  var lastError: Boolean = js.native
}

@injectable("LoginController")
class LoginController(scope: LoginScope, location: Location, rootScope: RootScope, backend: BackendService, val timeout: Timeout, val exceptionHandler: ExceptionHandler) extends AbstractController[LoginScope](scope) with AngularExecutionContextProvider {

  scope.username = ""
  scope.password = ""
  scope.remember = true
  scope.lastError = false

  @JSExport
  def login() = {
    if (scope.username.nonEmpty && scope.password.nonEmpty) {

      backend.login(scope.username, scope.password) onComplete {

        case Success(clientId) =>
          scope.password = ""
          rootScope.$emit("user.login")
          location.path("/")

        case Failure(e) =>
          // Login failed
          scope.password = ""
          scope.lastError = true
      }
    }
  }
}
