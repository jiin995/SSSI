import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DataFlow::PartialPathGraph

class ConstraintValidatorIsValidSource extends Method {
  ConstraintValidatorIsValidSource() {
      this.getName() = "isValid" 
      and 
      this.getDeclaringType().getASupertype().getName() = "ConstraintValidator<>"
  }
}

class BuildConstraintViolationWithTemplateSink extends MethodAccess {
  BuildConstraintViolationWithTemplateSink() {
      this.getMethod().getName() = "buildConstraintViolationWithTemplate" 
  }
}

class TaintFlowConfiguration extends TaintTracking::Configuration {
  TaintFlowConfiguration() { this = "TaintFlowConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m | 
        source.asParameter() = m.getParameter(0) 
        and 
        m.overridesOrInstantiates(any (ConstraintValidatorIsValidSource t))
      )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists (BuildConstraintViolationWithTemplateSink m | 
      sink.asExpr() = m.getArgument(0)
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma | 
        ma.getQualifier() = node1.asExpr() 
        and
        ma = node2.asExpr()
    ) 
    or
    exists( ConstructorCall c |
      c.getConstructedType().getSourceDeclaration().hasQualifiedName("java.util", "HashSet")
      and node1.asExpr() = c.getAnArgument() 
      and node2.asExpr() = c
    )
  }

  override int explorationLimit() { result = 100 }

}

/** 
from TaintFlowConfiguration config, DataFlow::Node sink
where config.isSink(sink)
select sink

from TaintFlowConfiguration config, DataFlow::Node source
where config.isSource(source)
select source
*/

from TaintFlowConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source,sink, "Contains unsanitized user data"

/*
from TaintFlowConfiguration cfg, DataFlow::PartialPathNode source, DataFlow::PartialPathNode sink
where
  cfg.hasPartialFlow(source, sink, _) 
  and source.getNode().getEnclosingCallable().getDeclaringType().getFile().getBaseName() = "SchedulingConstraintSetValidator.java"
select sink, source, sink, "Partial flow from unsanitized user data"
*/

/**Global Step propagation */
/*
class MyAdditionalTaintStep extends TaintTracking::AdditionalTaintStep{
  override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma | 
        ma.getQualifier() = node1.asExpr() and
        ma = node2.asExpr()
    ) or
    exists( ConstructorCall c |
      c.getConstructedType().getSourceDeclaration().hasQualifiedName("java.util", "HashSet")
      and node1.asExpr() = c.getAnArgument() 
      and node2.asExpr() = c
    )
  }
}
*/
